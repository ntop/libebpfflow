/*
 *
 * (C) 2019 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifdef __linux__
#include <linux/tcp.h>
#include <linux/udp.h>
#define th_sport source
#define th_dport dest
#define uh_sport source
#define uh_dport dest
#else
#include <netinet/tcp.h>
#include <netinet/udp.h>
#define s6_addr32 __u6_addr.__u6_addr32
#endif
#include "pcapio.c"
#include "ebpf_flow.h"

struct ebpf_event {
  u_int32_t pid, tid, uid, gid;
  char process_name[8];
  char container_id[12];
};

#define EBPFDUMP_INTERFACE       "ebpf"

#define SOCKET_LIBEBPF           2019
#define EXIT_SUCCESS             0

#define EBPFDUMP_MAX_NBPF_LEN    8192
#define EBPFDUMP_MAX_DATE_LEN    26
#define EBPFDUMP_MAX_NAME_LEN    4096

#define EBPFDUMP_VERSION_MAJOR   "0"
#define EBPFDUMP_VERSION_MINOR   "1"
#define EBPFDUMP_VERSION_RELEASE "0"

#define EXTCAP_OPT_LIST_INTERFACES	'l'
#define EXTCAP_OPT_VERSION		'v'
#define EXTCAP_OPT_LIST_DLTS		'L'
#define EXTCAP_OPT_INTERFACE		'i'
#define EXTCAP_OPT_CONFIG		'c'
#define EXTCAP_OPT_CAPTURE		'C'
#define EXTCAP_OPT_FIFO			'F'
#define EXTCAP_OPT_DEBUG		'D'
#define EBPFDUMP_OPT_HELP		'h'
#define EBPFDUMP_OPT_IFNAME		'n'
#define EBPFDUMP_OPT_CUSTOM_NAME	'N'

static struct option longopts[] = {
  /* mandatory extcap options */
  { "extcap-interfaces",	no_argument, 		NULL, EXTCAP_OPT_LIST_INTERFACES },
  { "extcap-version", 		optional_argument, 	NULL, EXTCAP_OPT_VERSION },
  { "extcap-dlts", 		no_argument, 		NULL, EXTCAP_OPT_LIST_DLTS },
  { "extcap-interface", 	required_argument, 	NULL, EXTCAP_OPT_INTERFACE },
  { "extcap-config", 		no_argument, 		NULL, EXTCAP_OPT_CONFIG },
  { "capture", 			no_argument, 		NULL, EXTCAP_OPT_CAPTURE },
  { "fifo", 			required_argument, 	NULL, EXTCAP_OPT_FIFO },
  { "debug", 			optional_argument, 	NULL, EXTCAP_OPT_DEBUG },

  /* custom extcap options */
  { "help", 			no_argument, 		NULL, EBPFDUMP_OPT_HELP        },
  { "ifname", 			required_argument,	NULL, EBPFDUMP_OPT_IFNAME      },
  { "custom-name", 		required_argument, 	NULL, EBPFDUMP_OPT_CUSTOM_NAME },

  {0, 0, 0, 0}
};

typedef struct _extcap_interface {
  const char * interface;
  const char * description;
  u_int16_t dlt;
  const char * dltname;
  const char * dltdescription;
} extcap_interface;

#define DLT_EN10MB 1

static extcap_interface extcap_interfaces[] = {
  { EBPFDUMP_INTERFACE, "eBPF interface", DLT_EN10MB, NULL, "The EN10MB Ethernet2 DLT" },
};

#define MAX_NUM_INT 32

static size_t extcap_interfaces_num = sizeof(extcap_interfaces) / sizeof(extcap_interface);
static char *extcap_selected_interface   = NULL;
static char *pcap_selected_interface     = NULL;
static char *extcap_capture_fifo         = NULL;
static FILE *fp                          = NULL;
static FILE *log_fp                      = NULL;
static char *all_interfaces[MAX_NUM_INT] = { NULL };
static u_int8_t num_all_interfaces       = 0;
static int32_t thiszone;
static char *containerId                 = NULL;

/* ***************************************************** */
/* ***************************************************** */

/* LRU cache */

#define NUM_LRU_ENTRIES   256

struct lru_cache_entry {
  u_int32_t key;
  u_int8_t is_full;
  struct ebpf_event value;
};

struct lru_cache {
  struct lru_cache_entry entries[NUM_LRU_ENTRIES];
};

void lru_cache_init(struct lru_cache *c) {
  memset(c, 0, sizeof(lru_cache));
}

u_int8_t lru_find_cache(struct lru_cache *c, u_int32_t key,
			struct ebpf_event *value) {
  u_int32_t slot = key % NUM_LRU_ENTRIES;

  if(c->entries[slot].is_full) {
    memcpy(value, &c->entries[slot].value, sizeof(struct ebpf_event));
    return(1);
  } else
    return(0);
}

void lru_add_to_cache(struct lru_cache *c, u_int32_t key, struct ebpf_event *value) {
  u_int32_t slot = key % NUM_LRU_ENTRIES;

  c->entries[slot].is_full = 1, c->entries[slot].key = key;
  memcpy(&c->entries[slot].value, value, sizeof(struct ebpf_event));
}

struct lru_cache received_events;

/* ***************************************************** */
/* ***************************************************** */

inline u_int min(u_int a, u_int b) { return((a < b) ? a : b); }

void sigproc(int sig) {
  fprintf(stdout, "Exiting...");
  fflush(stdout);
  exit(0);
}

/* ***************************************************** */

void extcap_version() {
  /* Print version */
  printf("extcap {version=%s.%s.%s}\n",
	 EBPFDUMP_VERSION_MAJOR, EBPFDUMP_VERSION_MINOR,
	 EBPFDUMP_VERSION_RELEASE);
}

/* ***************************************************** */

int docker_list_interfaces() {
  FILE *fd;
  int rc, found = 0;
  struct stat statbuf;
  const char *dcmd = "/usr/bin/docker";;
  char cmd[256];

  snprintf(cmd, sizeof(cmd), "%s ps --format '{{.Names}}'", dcmd);

  if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Executing %s\n", __FILE__, __LINE__, cmd);

  if((fd = popen(cmd, "r")) != NULL) {
    char line[1024];

    if(fgets(line, sizeof(line)-1, (FILE*) fd)) {
      char *tmp, *container = strtok_r(line, " ", &tmp);

      if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Read %s\n", __FILE__, __LINE__, line);

      while(container) {
	FILE *fd1;

	container[strlen(container)-1] = '\0'; /* Remove trailing \r */
	snprintf(cmd, sizeof(cmd), "%s exec %s bash -c 'cat /sys/class/net/eth0/iflink'", dcmd, container);

	if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Executing %s\n", __FILE__, __LINE__, cmd);

	if((fd1 = popen(cmd, "r")) != NULL) {
	  char netId[64];

	  if(fgets(netId, sizeof(netId)-1, (FILE*)fd1)) {
	    FILE *fd2;
	    
	    netId[strlen(netId)-1] ='\0';

	    if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Read %s\n", __FILE__, __LINE__, netId);

	    snprintf(cmd, sizeof(cmd), "/bin/grep -l %s /sys/class/net/veth*/ifindex", netId);
	    
	    if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Executing %s\n", __FILE__, __LINE__, cmd);
	    
	    if((fd2 = popen(cmd, "r")) != NULL) {
	      char ifname[128];

	      if(fgets(ifname, sizeof(ifname)-1, (FILE*)fd2)) {
		char *veth = &ifname[15];

		veth[11] = '\0';
		
		if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Read %s\n", __FILE__, __LINE__, veth);

		printf("value {arg=0}{value=%s@%s}{display=Container %s}\n", veth, container, container);
		found = 1;
	      }

	      fclose(fd2);
	    }
	  } else
	    if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] No output read :-(\n", __FILE__, __LINE__); 

	  fclose(fd1);
	} else {
	  if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Command failed :-(\n", __FILE__, __LINE__);
	}
	
	container = strtok_r(NULL, " ", &tmp);
      }
    }

    fclose(fd);
  }


  return(found);
}

/* ***************************************************** */

void kubectl_list_interfaces() {
  FILE *fd;
  int rc ;
  struct stat statbuf;
  const char *kcmd;
  char cmd[256];

  if(stat("/snap/bin/microk8s.kubectl", &statbuf) == 0)
    kcmd = "/snap/bin/microk8s.kubectl";
  else if(stat("/usr/bin/kubectl", &statbuf) == 0)
    kcmd = "/usr/bin/kubectl";
  else
    return; /* No kubectk */

  snprintf(cmd, sizeof(cmd), "%s get namespace -o 'jsonpath={.items[*].metadata.name}'",
	   kcmd);

  if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Executing %s\n", __FILE__, __LINE__, cmd);

  if((fd = popen(cmd, "r")) != NULL) {
    char line[1024];

    if(fgets(line, sizeof(line)-1, (FILE*) fd)) {
      char *tmp, *ns = strtok_r(line, " ", &tmp);

      if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Read %s\n", __FILE__, __LINE__, line);

      while(ns) {
	FILE *fd1;

	snprintf(cmd, sizeof(cmd), "%s get pod --namespace=%s -o jsonpath='{.items[*].metadata.name}'",
		 kcmd, ns);

	if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Executing %s\n", __FILE__, __LINE__, cmd);

	if((fd1 = popen(cmd, "r")) != NULL) {
	  char pod[512];

	  while(fgets(pod, sizeof(pod)-1, (FILE*)fd1)) {
	    char *tmp, *ns1;
	    FILE *fd2;

	    if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Read %s\n", __FILE__, __LINE__, pod);

	    ns1 = strtok_r(pod, " ", &tmp);

	    while(ns1 != NULL) {
	      snprintf(cmd, sizeof(cmd),
		       "%s exec %s --namespace=%s --  cat /sys/class/net/eth0/iflink 2>1 /dev/null",
		       kcmd, ns1, ns);

	      if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Executing %s\n", __FILE__, __LINE__, cmd);

	      if((fd2 = popen(cmd, "r")) != NULL) {
		char ids[32];

		while(fgets(ids, sizeof(ids)-1, (FILE*) fd2)) {
		  FILE *fd3;

		  if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Read %s\n", __FILE__, __LINE__, ids);

		  snprintf(cmd, sizeof(cmd), "ip -o link|grep ^%d:|cut -d ':' -f 2|cut -d '@' -f 1|tr -d '[:blank:]' | sed 's/\\n//g'",
			   atoi(ids));

		  if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Executing %s\n", __FILE__, __LINE__, cmd);

		  if((fd3 = popen(cmd, "r")) != NULL) {
		    char ifname[32];

		    if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Pipe open\n", __FILE__, __LINE__);
		    
		    while(fgets(ifname, sizeof(ifname)-1, (FILE*) fd3)) {
		      if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Read %s\n", __FILE__, __LINE__, ifname);

		      ifname[strlen(ifname)-1] = '\0';
		      printf("value {arg=0}{value=%s@%s}{display=Pod %s, Namespace %s}\n", ifname, ns1, ns1, ns);

		      if(num_all_interfaces < MAX_NUM_INT)
			all_interfaces[num_all_interfaces++] = strdup(ifname);
		    }

		    fclose(fd3);
		  } else {
		    if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] popen failed\n", __FILE__, __LINE__);
		  }
		}

		fclose(fd2);
	      } else {
		if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] popen failed\n", __FILE__, __LINE__);
	      }

	      ns1 = strtok_r(NULL, " ", &tmp);

	      if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] Next NS %s\n", __FILE__, __LINE__, ns1 ? ns1 : "<NULL>");
	    }
	  }

	  fclose(fd1);
	} else {
	  if(log_fp) fprintf(log_fp, "[DEBUG][%s:%u] popen failed\n", __FILE__, __LINE__);
	}
	
	ns = strtok_r(NULL, " ", &tmp);
      }
    }

    fclose(fd);
  }
}

/* ***************************************************** */

void print_pcap_interfaces() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *devpointer;

  if(pcap_findalldevs(&devpointer, errbuf) == 0) {
    int i = 0;

    while(devpointer) {
      if(devpointer->description == NULL) {
	u_int8_t found = 0, i;

	for(i=0; i<num_all_interfaces; i++)
	  if(strcmp(all_interfaces[i], devpointer->name) == 0) {
	    found = 1;
	    break;
	  }

	if(!found)
	  printf("value {arg=0}{value=%s}{display=%s}\n", devpointer->name, devpointer->name);
      }

      devpointer = devpointer->next;
    }
  }
}

/* ***************************************************** */

void extcap_list_all_interfaces() {
  u_int i;

  /* Add eBPF-only events */
  printf("value {arg=0}{value=%s}{display=eBPF Events}\n", "ebpfevents");

  /* Print kubernetes containers only if there are no docker containers */
  i = docker_list_interfaces();

  // if(i == 0)
    kubectl_list_interfaces();

  /* Print additional interfaces */
  print_pcap_interfaces();

  for(i=0; i<num_all_interfaces; i++)
    free(all_interfaces[i]);
}

/* ***************************************************** */

int extcap_print_help() {
  printf("Wireshark extcap eBPF plugin by ntop\n");

  printf("\nSupported command line options:\n");
  printf("--extcap-interfaces\n");
  printf("--extcap-version\n");
  printf("--extcap-dlts\n");
  printf("--extcap-interface <name>\n");
  printf("--extcap-config\n");
  printf("--capture\n");
  printf("--fifo <name>\n");
  printf("--debug\n");
  printf("--name <name>\n");
  printf("--custom-name <name>\n");
  printf("--help\n");

  return(0);
}

/* ***************************************************** */

void extcap_config() {
  u_int argidx = 0;

  if(!extcap_selected_interface) {
    extcap_print_help();
    return;
  }

  printf("arg {number=0}{call=--ifname}{display=Interface Name}"
	 "{type=selector}{tooltip=Network Interface from which packets will be captured}\n");

  extcap_list_all_interfaces();
}

/* ***************************************************** */

void extcap_list_interfaces() {
  u_int i;

  for(i = 0; i < extcap_interfaces_num; i++)
    printf("interface {value=%s}{display=%s}\n",
	   extcap_interfaces[i].interface,
	   extcap_interfaces[i].description);
}

/* ***************************************************** */

void extcap_dlts() {
  int i;

  if(!extcap_selected_interface) return;
  for(i = 0; i < extcap_interfaces_num; i++) {
    extcap_interface *eif = &extcap_interfaces[i];

    if(!strncmp(extcap_selected_interface, eif->interface, strlen(eif->interface))) {
      printf("dlt {number=%u}{name=%s}{display=%s}\n",
	     eif->dlt, eif->interface, eif->dltdescription);
      break;
    }
  }
}

/* ***************************************************** */

int exec_head(const char *bin, char *line, size_t line_len) {
  FILE *fp;

  fp = popen(bin, "r");

  if(fp == NULL)
    return -1;

  if(fgets(line, line_len-1, fp) == NULL) {
    pclose(fp);
    return -1;
  }

  pclose(fp);
  return 0;
}

/* ***************************************************** */

float wireshark_version() {
  char line[1035];
  char *version, *rev;
  float v = 0;

  if(exec_head("/usr/bin/wireshark -v", line, sizeof(line)) != 0 &&
      exec_head("/usr/local/bin/wireshark -v", line, sizeof(line)) != 0)
    return 0;

  version = strchr(line, ' ');
  if(version == NULL) return 0;
  version++;
  rev = strchr(version, '.');
  if(rev == NULL) return 0;
  rev++;
  rev = strchr(rev, '.');
  if(rev == NULL) return 0;
  *rev = '\0';

  sscanf(version, "%f", &v);

  return v;
}

/* ***************************************************** */

/* ******************************************** */
// ===== ===== IP ADDRESS TO STRING ===== ===== //
/* ******************************************** */

static char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    u_int byte = addr & 0xff;

    *--cp = byte % 10 + '0';
    byte /= 10;
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ***************************************************** */

static char* intoaV6(void *addr, char* buf, u_short bufLen) {
  char *ret = (char*)inet_ntop(AF_INET6, addr, buf, bufLen);

  if(ret == NULL)
    buf[0] = '\0';

  return(buf);
}

/* ***************************************************** */

static void IPV4Handler(eBPFevent *e, struct ipv4_addr_t *event, u_int32_t *hashval) {
  if(log_fp) {
    char buf1[32], buf2[32];

    fprintf(log_fp, "[addr: %s:%u <-> %s:%u]\n",
	 intoaV4(htonl(event->saddr), buf1, sizeof(buf1)), e->sport,
	 intoaV4(htonl(event->daddr), buf2, sizeof(buf2)), e->dport);
  }

  *hashval = e->proto + ntohl(event->saddr) + ntohl(event->daddr) + e->sport + e->dport;
}

/* ***************************************************** */

static void IPV6Handler(eBPFevent *e, struct ipv6_addr_t *event, u_int32_t *hashval) {
  u_int32_t *s = (u_int32_t*)&event->saddr;
  u_int32_t *d = (u_int32_t*)&event->daddr;

  if(log_fp) {
    char buf1[128], buf2[128];

    fprintf(log_fp, "[addr: %s:%u <-> %s:%u]\n",
	    intoaV6(&event->saddr, buf1, sizeof(buf1)), e->sport,
	    intoaV6(&event->daddr, buf2, sizeof(buf2)), e->dport);
  }

  *hashval = e->proto + e->sport + e->dport;

  *hashval += ntohl(s[0]) + ntohl(s[1]) + ntohl(s[2]) + ntohl(s[3])
      + ntohl(d[0]) + ntohl(d[1]) + ntohl(d[2]) + ntohl(d[3]);
}

/* ***************************************************** */

static void ebpf_process_event(void* t_bpfctx, void* t_data, int t_datasize) {
  eBPFevent *e = (eBPFevent*)t_data;
  u_int len = sizeof(eBPFevent)+32;
  char buf[len];
  struct timespec tp;
  struct timeval now;
  u_int64_t bytes_written = 0;
  int err;
  u_int32_t *null_sock_type = (u_int32_t*)buf;
  eBPFevent event;

  memcpy(&event, e, sizeof(eBPFevent)); /* Copy needed as ebpf_preprocess_event will modify the memory */
  ebpf_preprocess_event(&event);
  
  gettimeofday(&now, NULL);

  *null_sock_type = htonl(SOCKET_LIBEBPF);

  if(log_fp)
    fprintf(log_fp, "[ifname: %s][extcap: %s/pcap: %s]\n",
	    event.ifname,
	    extcap_selected_interface ? extcap_selected_interface : "",
	    pcap_selected_interface ? pcap_selected_interface : "");
  
  if(/* extcap_selected_interface || */
     pcap_selected_interface
     || (containerId && (strstr(event.container_id, containerId)))
     || (containerId && (!strcmp(event.kube.pod, containerId)))     
    ) {
    /*
      We are capturing from a physical interface and here we need
      to glue events with packets
    */

    if(log_fp) fprintf(log_fp, "==> [%s][%s][%s][%s][%s][%s]\n",
		       event.container_id, containerId, event.docker.name,
		       event.kube.name, event.kube.pod, event.kube.ns);
    
    if(
       (extcap_selected_interface  && (strcmp(event.ifname, extcap_selected_interface) == 0))
       || (pcap_selected_interface && (strcmp(event.ifname, pcap_selected_interface) == 0))
       || (containerId && event.docker.name && (!strcmp(event.docker.name, containerId)))
       || (containerId && event.kube.pod && (!strcmp(event.kube.pod, containerId)))
       ) {
      u_int32_t hashval = 0;
      struct ebpf_event evt;
      
      if(log_fp) {
	printf("[%s][%s][IPv4/%s][pid/tid: %u/%u [%s], uid/gid: %u/%u]"
	       "[father pid/tid: %u/%u [%s], uid/gid: %u/%u]",
	       event.ifname, event.sent_packet ? "Sent" : "Rcvd",
	       (event.proto == IPPROTO_TCP) ? "TCP" : "UDP",
	       event.proc.pid, event.proc.tid,
	       (event.proc.full_task_path == NULL) ? event.proc.task : event.proc.full_task_path,
	       event.proc.uid, event.proc.gid,
	       event.father.pid, event.father.tid,
	       (event.father.full_task_path == NULL) ? event.father.task : event.father.full_task_path,
	       event.father.uid, event.father.gid);

	if(event.ip_version == 4)
	  IPV4Handler(&event, &event.addr.v4, &hashval);
	else
	  IPV6Handler(&event, &event.addr.v6, &hashval);

	if(event.container_id[0] != '\0') {
	  printf("[containerID: %s]", event.container_id);

	  if(event.docker.name != NULL)
	    printf("[docker_name: %s]", event.docker.name);

	  if(event.kube.ns)  printf("[kube_name: %s]", event.kube.name);
	  if(event.kube.pod) printf("[kube_pod: %s]",  event.kube.pod);
	  if(event.kube.ns)  printf("[kube_ns: %s]",   event.kube.ns);
	}

	printf("[hashval: %u]\n", hashval);
      }

      if(!lru_find_cache(&received_events, hashval, &evt)) {
	u_int l; /* Trick to avoid silly compiler warnings */

	memset(&evt, 0, sizeof(evt));

	evt.pid = event.proc.pid, evt.tid = event.proc.tid,
	  evt.uid = event.proc.uid, evt.gid = event.proc.gid;

	l = min(sizeof(evt.process_name), strlen(event.proc.task));
	memcpy(evt.process_name, event.proc.task, l);

	l = min(sizeof(evt.container_id), strlen(event.container_id));
	memcpy(evt.container_id, event.container_id, l);

	if(log_fp)
	  fprintf(log_fp, "========>>>>>> Adding %u [process_name: %s][container_id: %s][pid: %u][tid: %u][uid: %u][gid: %u]\n",
		  hashval, evt.process_name, evt.container_id,
		  evt.pid, evt.tid, evt.uid, evt.gid);
	
	lru_add_to_cache(&received_events, hashval, &evt);
	// printf("++++ Adding %u\n", hashval);
      }

      /* ************************************************* */

      /* Uncomment for dumping events with packets */
#if 0
      memset(buf, 0, 14);
      memcpy(&buf[14], &event, sizeof(eBPFevent));
      if(!libpcap_write_packet(fp, now.tv_sec, now.tv_usec, len, len,
			       (const u_int8_t*)buf, &bytes_written, &err)) {
	time_t now = time(NULL);
	fprintf(stderr, "Error while writing packet @ %s", ctime(&now));
      } else
	fflush(fp); /* Flush buffer */
#endif
      
      /* ************************************************* */
    } else {
      if(log_fp)
	printf("Skipping event for interface %s\n", event.ifname);
    }
  } else {    
    memcpy(&buf[4], &event, sizeof(eBPFevent));
    
    if(!libpcap_write_packet(fp, now.tv_sec, now.tv_usec, len, len,
			     (const u_int8_t*)buf, &bytes_written, &err)) {
      time_t now = time(NULL);
      fprintf(stderr, "Error while writing packet @ %s", ctime(&now));
    } else
      fflush(fp); /* Flush buffer */
  }

  ebpf_free_event(&event);
}

/* ****************************************************** */

/*
 * A faster replacement for inet_ntoa().
 */
char* __intoa(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  u_int byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ************************************ */

static char buf[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"];

char* intoa(unsigned int addr) {
  return(__intoa(addr, buf, sizeof(buf)));
}

/* ************************************ */

static inline char* in6toa(struct in6_addr addr6) {
  snprintf(buf, sizeof(buf),
	   "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
	   addr6.s6_addr[0], addr6.s6_addr[1], addr6.s6_addr[2],
	   addr6.s6_addr[3], addr6.s6_addr[4], addr6.s6_addr[5], addr6.s6_addr[6],
	   addr6.s6_addr[7], addr6.s6_addr[8], addr6.s6_addr[9], addr6.s6_addr[10],
	   addr6.s6_addr[11], addr6.s6_addr[12], addr6.s6_addr[13], addr6.s6_addr[14],
	   addr6.s6_addr[15]);

  return(buf);
}

/* *************************************** */

int32_t gmt_to_local(time_t t) {
  int dt, dir;
  struct tm *gmt, *loc;
  struct tm sgmt;

  if (t == 0)
    t = time(NULL);
  gmt = &sgmt;
  *gmt = *gmtime(&t);
  loc = localtime(&t);
  dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
    (loc->tm_min - gmt->tm_min) * 60;

  /*
   * If the year or julian day is different, we span 00:00 GMT
   * and must add or subtract a day. Check the year first to
   * avoid problems when the julian day wraps.
   */
  dir = loc->tm_year - gmt->tm_year;
  if (dir == 0)
    dir = loc->tm_yday - gmt->tm_yday;
  dt += dir * 24 * 60 * 60;

  return (dt);
}

/* ****************************************************** */

const char* proto2str(u_short proto) {
  static char protoName[8];

  switch(proto) {
  case IPPROTO_TCP:  return("TCP");
  case IPPROTO_UDP:  return("UDP");
  case IPPROTO_ICMP: return("ICMP");
  default:
    snprintf(protoName, sizeof(protoName), "%d", proto);
    return(protoName);
  }
}

/* ****************************************************** */

static char hex[] = "0123456789ABCDEF";

char* etheraddr_string(const u_char *ep, char *buf) {
  u_int i, j;
  char *cp;

  cp = buf;
  if ((j = *ep >> 4) != 0)
    *cp++ = hex[j];
  else
    *cp++ = '0';

  *cp++ = hex[*ep++ & 0xf];

  for(i = 5; (int)--i >= 0;) {
    *cp++ = ':';
    if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
    else
      *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];
  }

  *cp = '\0';
  return (buf);
}

/* ***************************************************** */

void pcap_processs_packet(u_char *_deviceId,
			  const struct pcap_pkthdr *h,
			  const u_char *pkt) {
  struct ether_header ehdr;
  u_short eth_type, vlan_id;
  const u_char *p = pkt;
  char buf1[32], buf2[32];
  int s;
  struct tcphdr *tp;
  struct udphdr *up;
  u_int8_t proto = 0;
  u_int32_t hashval = 0;
  u_int64_t bytes_written = 0;
  int err;

  s = (h->ts.tv_sec + thiszone) % 86400;

  if(log_fp)
    fprintf(log_fp, "%02d:%02d:%02d.%06u ",
	   s / 3600, (s % 3600) / 60, s % 60,
	   (unsigned)h->ts.tv_usec);

  memcpy(&ehdr, p, sizeof(struct ether_header));
  eth_type = ntohs(ehdr.ether_type);

  if(log_fp)
    fprintf(log_fp, "[%s -> %s] ",
	   etheraddr_string(ehdr.ether_shost, buf1),
	   etheraddr_string(ehdr.ether_dhost, buf2));

  if(eth_type == 0x8100) {
    vlan_id = (p[14] & 15)*256 + p[15];
    eth_type = (p[16])*256 + p[17];

    if(log_fp)
      fprintf(log_fp, "[vlan %u] ", vlan_id);

    p += 4;
  }

  p += sizeof(ehdr);

  if(eth_type == 0x0800) {
    struct ip *ip = (struct ip*)p;

    proto = ip->ip_p;

    if(log_fp) {
      fprintf(log_fp, "[%s]", proto2str(ip->ip_p));
      fprintf(log_fp, "[%s ", intoa(ntohl(ip->ip_src.s_addr)));
      fprintf(log_fp, "-> %s]", intoa(ntohl(ip->ip_dst.s_addr)));
    }

    hashval = proto + ntohl(ip->ip_src.s_addr) + ntohl(ip->ip_dst.s_addr);

    p += ((u_int16_t)ip->ip_hl * 4);
  } else if(eth_type == 0x86DD) {
    struct ip6_hdr *ip6 = (struct ip6_hdr*)p;

    proto = ip6->ip6_nxt;

    if(log_fp) {
      fprintf(log_fp, "[%s ", in6toa(ip6->ip6_src));
      fprintf(log_fp, "-> %s]", in6toa(ip6->ip6_dst));
    }
      
    hashval = proto
      + ntohl(ip6->ip6_src.s6_addr32[0])
      + ntohl(ip6->ip6_src.s6_addr32[1])
      + ntohl(ip6->ip6_src.s6_addr32[2])
      + ntohl(ip6->ip6_src.s6_addr32[3])
      + ntohl(ip6->ip6_dst.s6_addr32[0])
      + ntohl(ip6->ip6_dst.s6_addr32[1])
      + ntohl(ip6->ip6_dst.s6_addr32[2])
      + ntohl(ip6->ip6_dst.s6_addr32[3]);

    p += sizeof(struct ip6_hdr)+htons(ip6->ip6_plen);
  } else if(eth_type == 0x0806) {
    if(log_fp)
      fprintf(log_fp, "[ARP]");
  } else {
    if(log_fp)
      fprintf(log_fp, "[eth_type=0x%04X]", eth_type);
  }

  if(proto) {
    if(log_fp) fprintf(log_fp, "[%s]", proto2str(proto));

    switch(proto) {
    case IPPROTO_TCP:
      {
	struct tcphdr *t = (struct tcphdr*)p;

	if(log_fp)
	  fprintf(log_fp, "[%u -> %u]", ntohs(t->th_sport), ntohs(t->th_dport));

	hashval += ntohs(t->th_sport) + ntohs(t->th_dport);
      }
      break;
    case IPPROTO_UDP:
      {
	struct udphdr *u = (struct udphdr*)p;;

	if(log_fp)
	  fprintf(log_fp, "[%u -> %u]", ntohs(u->uh_sport), ntohs(u->uh_dport));

	hashval += ntohs(u->uh_sport) + ntohs(u->uh_dport);
      }
      break;
    }
  }

  if(log_fp)
    fprintf(log_fp, "[caplen=%u][len=%u][hashval=%u]\n", h->caplen, h->len, hashval);

  // if(log_fp) fprintf(log_fp, "[caplen=%u][len=%u][hashval=%u]\n", h->caplen, h->len, hashval);

  if(fp) {
    struct ebpf_event evt;

    if(lru_find_cache(&received_events, hashval, &evt)) {
      char *packet;
      u_int new_len = h->caplen + sizeof(struct ebpf_event) + 2;

      // fprintf(log_fp, "++++ Found  %u\n", hashval);

      packet = (char*)malloc(new_len);

      if(packet) {
	if(log_fp)
	  fprintf(log_fp, "========>>>>>> Reading %u [process_name: %s][container_id: %s][pid: %u][tid: %u][uid: %u][gid: %u][len: %u -> %u]\n",
		  hashval, evt.process_name, evt.container_id,
		  evt.pid, evt.tid, evt.uid, evt.gid,
		  h->caplen, new_len);
	
	memcpy(packet, pkt, h->caplen);
	packet[h->caplen] = 0x19;
	packet[h->caplen+1] = 0x68;
	memcpy(&packet[h->caplen+2], &evt, sizeof(evt));

	if(!libpcap_write_packet(fp, h->ts.tv_sec, h->ts.tv_usec, new_len, new_len,
				 (const u_int8_t*)packet, &bytes_written, &err)) {
	  time_t now = time(NULL);
	  fprintf(stderr, "Error while writing packet @ %s", ctime(&now));
	} else
	  fflush(fp); /* Flush buffer */

	free(packet);
      }
    } else {
      if(!libpcap_write_packet(fp, h->ts.tv_sec, h->ts.tv_usec, h->caplen, h->len,
			       (const u_int8_t*)pkt, &bytes_written, &err)) {
	time_t now = time(NULL);
	fprintf(stderr, "Error while writing packet @ %s", ctime(&now));
      } else
	fflush(fp); /* Flush buffer */
    }
  }
}

/* ***************************************************** */

void extcap_capture() {
  ebpfRetCode rc;
  void *ebpf;
  u_int num = 0;
  u_int64_t bytes_written = 0;
  int err;
  u_int8_t success;
  pcap_t *pd = NULL;
  int promisc = 1;
  int snaplen = 1600;
  char errbuf[PCAP_ERRBUF_SIZE];
  
  if(log_fp)
    fprintf(log_fp, "[DEBUG][%s:%u] Capturing [ifname: %s][fifo: %s]\n",
	   __FILE__, __LINE__,
	   pcap_selected_interface ? pcap_selected_interface : "<NULL>",
	   extcap_capture_fifo ? extcap_capture_fifo : "<NULL>");

  if(log_fp)
    fprintf(log_fp, "[DEBUG][%s:%u] Capturing [ifname: %s][fifo: %s]\n",
	    __FILE__, __LINE__,
	    pcap_selected_interface ? pcap_selected_interface : "<NULL>",
	    extcap_capture_fifo ? extcap_capture_fifo : "<NULL>");

  ebpf = init_ebpf_flow(NULL, ebpf_process_event, &rc, 0xFFFF);

  if(ebpf == NULL) {
    fprintf(stderr, "Unable to initialize libebpfflow\n");
    return;
  }

  if(pcap_selected_interface) {
    char *at = strchr(pcap_selected_interface, '@');

    if(at) {
      at[0] = '\0';
      containerId = &at[1];
    }
  }
  
  if((fp = fopen(extcap_capture_fifo, "wb")) == NULL) {
    fprintf(stderr, "Unable to create file %s", extcap_capture_fifo);
    return;
  }

  if(!libpcap_write_file_header(fp,
				pcap_selected_interface ? DLT_EN10MB : 0 /* DLT_NULL */,
				pcap_selected_interface ? 2048:  sizeof(eBPFevent), FALSE, &bytes_written, &err)) {
    fprintf(stderr, "Unable to write file %s header", extcap_capture_fifo);
    return;
  }

  if((signal(SIGINT, sigproc) == SIG_ERR)
     || (signal(SIGTERM, sigproc) == SIG_ERR)
     || (signal(SIGQUIT, sigproc) == SIG_ERR)) {
    fprintf(stderr, "Unable to install SIGINT/SIGTERM signal handler");
    return;
  }

  if(pcap_selected_interface) {
    if((pd = pcap_open_live(pcap_selected_interface, snaplen, promisc, 1, errbuf)) == NULL) {
      printf("pcap_open_live: %s\n", errbuf);
      return;
    }

    if(log_fp) fprintf(log_fp, "Reading packets from %s\n", pcap_selected_interface);

    while(1) {
      if(pcap_dispatch(pd, 1, pcap_processs_packet, NULL) < 0) break;
      ebpf_poll_event(ebpf, 1);
    }

    pcap_close(pd);
  } else {
    /* eBPF-only capture */

    while(1) {
      /* fprintf(stderr, "%u\n", ++num); */
      ebpf_poll_event(ebpf, 10);
    }
  }

  term_ebpf_flow(ebpf);

  fclose(fp);
}

/* ***************************************************** */

int main(int argc, char *argv[]) {
  int option_idx = 0, result;
  time_t epoch;
  char date_str[EBPFDUMP_MAX_DATE_LEN];
  struct tm* tm_info;

  thiszone = gmt_to_local(0);
  lru_cache_init(&received_events);

  log_fp = fopen("/tmp/ebpfdump.log", "w");

#if 0
  /* test code */
  if(0) {
    eBPFevent x;

    printf("%d\n", offsetof(eBPFevent, proc));
    printf("%d\n", offsetof(eBPFevent, father));

    return(0);
  }
#endif

  if(argc == 1) {
    extcap_print_help();
    return EXIT_SUCCESS;
  }

  u_int defer_dlts = 0, defer_config = 0, defer_capture = 0;
  while((result = getopt_long(argc, argv, "h", longopts, &option_idx)) != -1) {
    // fprintf(stderr, "OPT: '%c' VAL: '%s' \n", result, optarg != NULL ? optarg : "");

    switch(result) {
      /* mandatory extcap options */
    case EXTCAP_OPT_DEBUG:
      break;
    case EXTCAP_OPT_LIST_INTERFACES:
      extcap_version();
      extcap_list_interfaces();
      defer_dlts = defer_config = defer_capture = 0;
      break;
    case EXTCAP_OPT_VERSION:
      extcap_version();
      defer_dlts = defer_config = defer_capture = 0;
      break;
    case EXTCAP_OPT_LIST_DLTS:
      defer_dlts = 1; defer_config = defer_capture = 0;
      break;
    case EXTCAP_OPT_INTERFACE:
      extcap_selected_interface = strndup(optarg, EBPFDUMP_MAX_NAME_LEN);
      break;
    case EXTCAP_OPT_CONFIG:
      defer_config = 1; defer_dlts = defer_capture = 0;
      break;
    case EXTCAP_OPT_CAPTURE:
      defer_capture = 1; defer_dlts = defer_config = 0;
      break;
      break;
    case EXTCAP_OPT_FIFO:
      extcap_capture_fifo = strdup(optarg);
      break;

      /* custom ebpfdump options */
    case EBPFDUMP_OPT_IFNAME:
      if(strcmp(optarg, "ebpfevents") != 0)
	pcap_selected_interface = strdup(optarg);
      break;

    case EBPFDUMP_OPT_HELP:
      extcap_print_help();
      return EXIT_SUCCESS;
      break;
    }
  }

  if(defer_dlts) extcap_dlts();
  else if(defer_config) extcap_config();
  else if(defer_capture) extcap_capture();

  if(extcap_selected_interface)   free(extcap_selected_interface);
  if(extcap_capture_fifo)         free(extcap_capture_fifo);

  if(log_fp) fclose(log_fp);

  return EXIT_SUCCESS;
}
