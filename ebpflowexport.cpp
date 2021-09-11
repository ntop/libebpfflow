/*
 *
 * (C) 2018-21 - ntop.org
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <stdio.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <regex>

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <climits>
#include <bcc/BPF.h>
#include <zmq.h>
#include <json-c/json.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "ebpf_flow.h"


void help();
static char* intoaV4(unsigned int addr, char* buf, u_short bufLen);
char* intoaV6(unsigned __int128 addr, char* buf, u_short bufLen);
static void handleTermination(int t_s=0);
static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize);
static void zmqHandler(void* t_bpfctx, void* t_data, int t_datasize);
static u_int8_t verbose = 0;
static int  gRUNNING = 1;
void *gZMQsocket = NULL;

/* **************************** */
// ===== ===== MAIN ===== ===== //
/* **************************** */

struct zmq_msg_hdr {
  char url[32];
  u_int32_t version;
  u_int32_t size;
};

static const struct option long_opts[] = {
  { "retr",     0, NULL, 'r' },
  { "tcpclose", 0, NULL, 'c' },
  { "udp",      0, NULL, 'u' },
  { "tcp",      0, NULL, 't' },
  { "in",       0, NULL, 'i' },
  { "out",      0, NULL, 'o' },
  { "help",     0, NULL, 'h' },
  { "zmq",      0, NULL, 'z' },
  { "verbose",  0, NULL, 'v' },
  { NULL,       0, NULL,  0  }
};

int main(int argc, char **argv) {
  int ch;
  char* zmq_endpoint = NULL;
  void *context = NULL, *ebpf = NULL;
  short flags = 0;
  ebpfRetCode rc = ebpf_no_error;
  eBPFHandler handler = ebpfHandler;

  signal(SIGINT, handleTermination);

  // Argument Parsing ----- //
  while ((ch = getopt_long(argc, argv, "z:rcutiohv", long_opts, NULL)) != EOF) {
    switch (ch) {
    case 'u':
      flags |= LIBEBPF_UDP;
      break;
    case 't':
      flags |= LIBEBPF_TCP;
      break;
    case 'i':
      flags |= LIBEBPF_INCOMING;
      break;
    case 'o':
      flags |= LIBEBPF_OUTCOMING;
      break;
    case 'c':
      flags |= LIBEBPF_TCP_CLOSE;
      break;
    case 'r':
      flags |= LIBEBPF_TCP_RETR;
      break;
    case 'z':
      zmq_endpoint = strdup(optarg);
      handler = zmqHandler;
      break;
    case 'v':
      verbose = 1;
      break;
    default:
      help();
      return 0;
    }
  }
  // Setting defaults
  if(flags == 0)
    flags = 0xffff;

  if(!(flags & LIBEBPF_INCOMING) && !(flags & LIBEBPF_OUTCOMING))
    flags += LIBEBPF_INCOMING | LIBEBPF_OUTCOMING;

  if(!(flags & LIBEBPF_TCP) && !(flags & LIBEBPF_UDP)
     && !(flags & LIBEBPF_TCP_CLOSE) && !(flags & eTCP_RETR))
    flags += (LIBEBPF_UDP | LIBEBPF_TCP) | LIBEBPF_TCP_CLOSE;

  // Checking root ----- //
  if(getuid() != 0) {
    //printf("Please run as root user \n");
    help();
    return 0;
  }

  printf("Welcome to ebpflowexport v.%s\n(C) 2018-21 ntop.org\n",
	 ebpf_flow_version());

  if(zmq_endpoint) {
    context = zmq_ctx_new();
    if(context == NULL) {
      printf("Unable to initialize ZMQ context");
      goto close;
    }

    gZMQsocket = zmq_socket(context, ZMQ_PUB);
    if(gZMQsocket == NULL) {
      printf("Unable to create ZMQ socket");
      goto close;  
    }

    if(zmq_endpoint[strlen(zmq_endpoint) - 1] == 'c') {
      /* Collector mode */
      if(zmq_connect(gZMQsocket, zmq_endpoint) != 0)
        printf("Unable to connect to ZMQ socket %s: %s\n", zmq_endpoint, strerror(errno));
    } else {
      /* Probe mode */
      if(zmq_bind(gZMQsocket, zmq_endpoint) != 0) {
        printf("Unable to bind to ZMQ socket %s: %s\n", zmq_endpoint, strerror(errno));
        goto close;
      }
    }
  }

  // Activating libebpflow ----- //
  printf("Initializing eBPF [%s]...\n",
#ifdef NEW_EBF
	 "New API"
#else
	 "Legacy API"
#endif
	 );
  ebpf = init_ebpf_flow(NULL, handler, &rc, flags);
  
  if(!ebpf) {
    printf("Unable to initialize libebpfflow: %s\n", ebpf_print_error(rc));
    goto close;
  }

  printf("eBPF initializated successfully\n");

  // Polling event ----- //
  while(gRUNNING) {
    ebpf_poll_event(ebpf, 10);  
  }

  // Cleaning and terminating ----- //
 close:
  if(gZMQsocket != NULL)
    zmq_close(gZMQsocket);
  if(context != NULL) 
    zmq_ctx_destroy(context);
  if(zmq_endpoint)
    free(zmq_endpoint);
  
  term_ebpf_flow(ebpf);
  printf("eBPF terminated\n");

  return(rc);
}

void help() {
  printf(
	 "(C) 2018-21 - ntop.org\n"
	 "ebpflowexport: Traffic visibility tool based on libebpfflow. By default all events will be shown\n"
	 "Termination: CTRL-C\n"
	 "Usage: ebpflowexport [ OPTIONS ]\n"
	 "   -h, --help        display this message\n"
	 "   -v                Verbose\n"
	 "   -t, --tcp         TCP events\n"
	 "   -u, --udp         UDP events\n"
	 "   -i, --in          Incoming events (i.e. TCP accept and UDP receive)\n"
	 "   -o, --on          Outgoing events (i.e. TCP connect and UDP send)\n"
	 "   -r, --retr        Retransmissions events\n"
	 "   -c, --tcpclose    TCP connection refused and socket close \n"
	 "   -z, --zmq <port>  Publish JSON events as a ZeroMQ publisher with envelope 'ebpfflow'\n"
	 "                     Example:\n"
	 "                     - ebpflowexport -z tcp://127.0.0.1:1234\n"
	 "                     - ebpflowexport -z tcp://127.0.0.1:6789c [for Wireshark]\n\n"
	 "IMPORTANT: please run this tool as root\n"
	 );
}


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

static char* intoaV6(void *addr, char* buf, u_short bufLen) {
  char *ret = (char*)inet_ntop(AF_INET6, addr, buf, bufLen);

  if(ret == NULL)
    buf[0] = '\0';

  return(buf);
}


/* ***************************************** */
// ===== ===== CALLBACK HANDLERS ===== ===== //
/* ***************************************** */

const char* event_summary(eBPFevent* e) {
  switch(e->etype) {
  case eTCP_ACPT:
    return("ACCEPT");
    break;
  case eTCP_CONN:
    return("CONNECT");
    break;
  case eTCP_CONN_FAIL:
    return("CONNECT_FAILED");
    break;
  case eTCP_CLOSE:
    return("CLOSE");
    break;
  case eTCP_RETR:
    return("RETRANSMIT");
    break;
  case eUDP_SEND:
    return("SEND");
    break;
  case eUDP_RECV:
    return("RECV");
    break;
  }

  return("???");
}

/* ***************************************************** */
/* ***************************************************** */

static void IPV4Handler(void* t_bpfctx, eBPFevent *e, struct ipv4_addr_t *event) {
  char buf1[32], buf2[32];

  printf("[addr: %s:%u <-> %s:%u]",
	 intoaV4(htonl(event->saddr), buf1, sizeof(buf1)), e->sport,
	 intoaV4(htonl(event->daddr), buf2, sizeof(buf2)), e->dport);
}

static void IPV6Handler(void* t_bpfctx, eBPFevent *e, struct ipv6_addr_t *event) {
  char buf1[128], buf2[128];

  printf("[addr: %s:%u <-> %s:%u]",
	 intoaV6(&event->saddr, buf1, sizeof(buf1)), e->sport,
	 intoaV6(&event->daddr, buf2, sizeof(buf2)), e->dport);
}

/* ***************************************************************** */

static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize) {
  eBPFevent *e = (eBPFevent*)t_data;
  eBPFevent event;
  struct timespec tp;
  
  memcpy(&event, e, sizeof(eBPFevent)); /* Copy needed as ebpf_preprocess_event will modify the memory */

  ebpf_preprocess_event(&event);

  clock_gettime(CLOCK_MONOTONIC, &tp);

#if 0
  printf("[latency %.1f usec] ",
	 (float)(tp.tv_nsec-(event.ktime % 1000000000))/(float)1000);
#endif

  printf("%u.%06u ", (unsigned int)event.event_time.tv_sec, (unsigned int)event.event_time.tv_usec);

  printf("[%s][%s][IPv4/%s][pid/tid: %u/%u [%s%s%s], uid/gid: %u/%u][father pid/tid: %u/%u [%s%s%s], uid/gid: %u/%u]",
	 event.ifname, event.sent_packet ? "Sent" : "Rcvd",
	 (event.proto == IPPROTO_TCP) ? "TCP" : "UDP",
	 event.proc.pid, event.proc.tid,
	 (event.proc.full_task_path == NULL) ? event.proc.task : event.proc.full_task_path,
	 (event.proc.cmdline == NULL) ? "" : " ",
	 (event.proc.cmdline == NULL) ? "" : event.proc.cmdline,
	 event.proc.uid, event.proc.gid,
	 event.father.pid, event.father.tid,
	 (event.father.full_task_path == NULL) ? event.father.task : event.father.full_task_path,
	 (event.father.cmdline == NULL) ? "" : "",
	 (event.father.cmdline == NULL) ? "": event.father.cmdline,
	 event.father.uid, event.father.gid);

  if(event.ip_version == 4)
    IPV4Handler(t_bpfctx, &event, &event.addr.v4);
  else
    IPV6Handler(t_bpfctx, &event, &event.addr.v6);

  if(event.proto == IPPROTO_TCP) {
    printf("[%s]", event_summary(&event));
    
    if(event.etype == eTCP_CONN)
      printf("[latency: %.2f msec]", ((float)event.latency_usec)/(float)1000);
  }
  
  // Container ----- /'/
  if(event.container_id[0] != '\0') {
    printf("[containerID: %s]", event.container_id);
    
    if(event.docker.name != NULL)
      printf("[docker_name: %s]", event.docker.name);

    if(event.kube.ns)  printf("[kube_name: %s]", event.kube.name);
    if(event.kube.pod) printf("[kube_pod: %s]",  event.kube.pod);
    if(event.kube.ns)  printf("[kube_ns: %s]",   event.kube.ns);
  }

  printf("\n");
  ebpf_free_event(&event);
}

/* ******************************************* */

void task2json(struct taskInfo *t, struct json_object **t_res) {
  struct json_object *j = json_object_new_object();
  struct passwd *uid_info;
  struct group *gg;
  
  json_object_object_add(j, "PID", json_object_new_int(t->pid));

  json_object_object_add(j, "UID", json_object_new_int(t->uid));
  if((uid_info = getpwuid(t->pid)) != NULL)
    json_object_object_add(j, "UID_NAME", json_object_new_string(uid_info->pw_name));
  
  json_object_object_add(j, "GID", json_object_new_int(t->gid));
  
  if((gg = getgrgid(t->gid)) != NULL)	
    json_object_object_add(j, "GID_NAME", json_object_new_string(gg->gr_name));

  json_object_object_add(j, "TID", json_object_new_int(t->tid));

  json_object_object_add(j, "PROCESS_PATH", 
			 json_object_new_string(t->full_task_path != NULL ? t->full_task_path : t->task));

  json_object_object_add(j, "PROCESS_CMDLINE", 
			 json_object_new_string(t->cmdline != NULL ? t->cmdline : ""));
  
  *t_res = j;
}

/* ******************************************* */

void event2json(eBPFevent *t_event, struct json_object **t_res) {
  char buf1[128], buf2[128];
  char *saddr, *daddr;
  const char *t_saddr, *t_daddr;
  struct json_object *j = json_object_new_object(), *k, *docker_json, *kube_json;
  struct json_object *proc, *father;
  
  snprintf(buf1, sizeof(buf1), "%u.%06u",
	   (unsigned int)t_event->event_time.tv_sec,
	   (unsigned int)t_event->event_time.tv_usec);
  json_object_object_add(j, "timestamp", json_object_new_string(buf1));

  // json_object_object_add(j, "ktime", json_object_new_int64(t_event->ktime));
  
  json_object_object_add(j, "INTERFACE_NAME", json_object_new_string(t_event->ifname));
  json_object_object_add(j, "IP_PROTOCOL_VERSION", json_object_new_int(t_event->ip_version));

  json_object_object_add(j,
			 (t_event->proto == IPPROTO_TCP) ? "TCP_EVENT_TYPE" : "UDP_EVENT_TYPE",
			 json_object_new_string(event_summary(t_event)));

  if(t_event->ip_version == 4) {
    saddr = intoaV4(htonl(t_event->addr.v4.saddr), buf1, sizeof(buf1));
    daddr = intoaV4(htonl(t_event->addr.v4.daddr), buf2, sizeof(buf2));
    t_saddr = "IPV4_SRC_ADDR", t_daddr  = "IPV4_DST_ADDR";
  } else {
    saddr = intoaV6(&t_event->addr.v6.saddr, buf1, sizeof(buf1));
    daddr = intoaV6(&t_event->addr.v6.daddr, buf2, sizeof(buf2));
    t_saddr = "IPV6_SRC_ADDR", t_daddr  = "IPV6_DST_ADDR";
  }

  json_object_object_add(j, t_saddr, json_object_new_string(saddr));
  json_object_object_add(j, t_daddr, json_object_new_string(daddr));
  
  json_object_object_add(j, "PROTOCOL", json_object_new_int(t_event->proto));
  json_object_object_add(j, "L4_SRC_PORT", json_object_new_int(t_event->sport));
  json_object_object_add(j, "L4_DST_PORT", json_object_new_int(t_event->dport));

  if(t_event->latency_usec > 0) {
    double v = t_event->latency_usec/(double)1000;

    snprintf(buf1, sizeof(buf1), "%.3f", v);
    
#ifdef HAVE_DOUBLES
    json_object_object_add(j, "NW_LATENCY_MS", json_object_new_double_s(v, buf1));
#else
    json_object_object_add(j, "NW_LATENCY_MS", json_object_new_string(buf1));
#endif
  }
  
  if(t_event->retransmissions > 0)
    json_object_object_add(j, "RETRAN_PKTS", json_object_new_int(t_event->retransmissions));

  if(t_event->proc.task[0] != '\0') {
    task2json(&t_event->proc, &proc);
    json_object_object_add(j, "LOCAL_PROCESS", proc);
  }

  if(t_event->father.task[0] != '\0') {
    task2json(&t_event->father, &father);
    json_object_object_add(j, "LOCAL_FATHER_PROCESS", father);
  }
  
  if(t_event->docker.name != NULL) {
    if((k = json_object_new_object()) != NULL) {
      if((docker_json = json_object_new_object()) != NULL) {	
	if(t_event->container_id[0] != '\0')
	  json_object_object_add(docker_json, "ID", json_object_new_string(t_event->container_id));
	
	json_object_object_add(docker_json, "NAME", json_object_new_string(t_event->docker.name));
	json_object_object_add(k, "DOCKER", docker_json);
	json_object_object_add(j, "LOCAL_CONTAINER", k);
      } else
	json_object_put(k);
    }
  }
  
  if(t_event->kube.pod) {
    if((k = json_object_new_object()) != NULL) {
      if((kube_json = json_object_new_object()) != NULL) {
	if(t_event->container_id[0] != '\0')
	  json_object_object_add(kube_json, "ID", json_object_new_string(t_event->container_id));
	
	if(t_event->kube.name != NULL)
	  json_object_object_add(kube_json, "NAME", json_object_new_string(t_event->kube.name));
	
	if(t_event->kube.pod != NULL)
	  json_object_object_add(kube_json, "POD", json_object_new_string(t_event->kube.pod));
	
	if(t_event->kube.ns != NULL)
	  json_object_object_add(kube_json, "NS", json_object_new_string(t_event->kube.ns));
	
	json_object_object_add(k, "K8S", kube_json);
	json_object_object_add(j, "LOCAL_CONTAINER", k);
      } else
	json_object_put(k);
    }
  }
  
  *t_res = j;
}

/* ******************************************* */

static void zmqHandler(void* t_bpfctx, void* t_data, int t_datasize) { 
  struct json_object *json_event;
  char *json_str;
  eBPFevent *e = (eBPFevent*)t_data;
  eBPFevent event;
  
  memcpy(&event, e, sizeof(eBPFevent));
  ebpf_preprocess_event(&event);
  event2json(&event, &json_event);
  json_str = (char*) json_object_get_string(json_event);

  if(verbose) printf("%s\n", json_str);
  
  // writing event ----- //
  struct zmq_msg_hdr msg_hdr;

  /* 1 Send the event in JSON format */
  strncpy(msg_hdr.url, "flow", sizeof(msg_hdr.url));
  msg_hdr.version = 0;
  msg_hdr.size = strlen(json_str);
  zmq_send(gZMQsocket, &msg_hdr, sizeof(msg_hdr), ZMQ_SNDMORE);
  zmq_send(gZMQsocket, json_str, msg_hdr.size, 0);

  /* 2 Send the event in binary format */
  strncpy(msg_hdr.url, "ebpf", sizeof(msg_hdr.url));
  msg_hdr.version = 0;
  msg_hdr.size = sizeof(eBPFevent);
  zmq_send(gZMQsocket, &msg_hdr, sizeof(msg_hdr), ZMQ_SNDMORE);
  zmq_send(gZMQsocket, &event, msg_hdr.size, 0);

  json_object_put(json_event);
  ebpf_free_event(&event);
}  

/* ******************************************* */

static void handleTermination(int t_s) {
  if(!gRUNNING) return;

  printf("\r* Terminating * \n");
  gRUNNING = 0;
}
