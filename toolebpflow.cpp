/*
 *
 * (C) 2018-19 - ntop.org
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

#include "ebpf_flow.h"


using namespace std;

void help();
static char* intoaV4(unsigned int addr, char* buf, u_short bufLen);
char* intoaV6(unsigned __int128 addr, char* buf, u_short bufLen);
void event_summary (eBPFevent* e, char* t_buffer, int t_size);
static void handleTermination(int t_s=0);
static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize);
static void zmqHandler(void* t_bpfctx, void* t_data, int t_datasize);

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
  { NULL,       0, NULL,  0  }
};

int main(int argc, char **argv) {
  int ch, zmq_port = -1;
  char zmq_url[14];
  void *context, *ebpf = NULL;
  short flags = 0;
  ebpfRetCode rc = ebpf_no_error;
  eBPFHandler handler = ebpfHandler;

  signal(SIGINT, handleTermination);

  // Argument Parsing ----- //
  while ((ch = getopt_long(argc, argv, "z:rcutioh", long_opts, NULL)) != EOF) {
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
      zmq_port = atoi(optarg);
      if(zmq_port == 0) {
        printf("Invalid port number: %s \n", optarg);
        help();
        return -1;
      }
      snprintf(zmq_url, sizeof(zmq_url), "tcp://*:%d", zmq_port);
      handler = zmqHandler;
      break;
    default:
      help();
      return 0;
    }
  }
  // Setting defaults
  if(flags==0)
    flags = 0xffff;

  if(!(flags & LIBEBPF_INCOMING) && !(flags & LIBEBPF_OUTCOMING))
    flags += LIBEBPF_INCOMING | LIBEBPF_OUTCOMING;

  if(!(flags & LIBEBPF_TCP) && !(flags & LIBEBPF_UDP)
      && !(flags & LIBEBPF_TCP_CLOSE) && !(flags & eTCP_RETR))
    flags += (LIBEBPF_UDP | LIBEBPF_TCP) | LIBEBPF_TCP_CLOSE;

  // Checking root ----- //
  if(getuid() != 0) {
    printf("Please run as root user \n");
    help();
    return 0;
  }

  printf("Welcome to toolebpflow v.%s\n(C) 2018-19 ntop.org\n",
    ebpf_flow_version());

  // ZMQ socket initialization ----- //
  if(zmq_port > 0) {
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
    if(zmq_bind(gZMQsocket, zmq_url) != 0) {
      printf("Unable to bind ZMQ socket to port %d: %s\n", zmq_port, strerror(errno));
      goto close;
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
  
  term_ebpf_flow(ebpf);
  printf("eBPF terminated\n");

  return(rc);
}

void help() {
  printf(
   "toolebpflow: Traffic visibility tool based on libebpfflow. By default all events will be shown \n"
   "Termination: CTRL-C \n"
   "Usage: ebpflow [ OPTIONS ] \n"
   "   -h, --help        display this message \n"
   "   -t, --tcp         TCP events \n"
   "   -u, --udp         UDP events \n"
   "   -i, --in          incoming events (i.e. TCP accept and UDP receive) \n"
   "   -o, --on          outgoing events (i.e. TCP connect and UDP send) \n"
   "   -r, --retr        retransmissions events \n"
   "   -c, --tcpclose    TCP close events \n"
   "   -z, --zmq <port>  publish json events as a ZeroMQ publisher with envelope 'ebpfflow' \n"
   "Note: please run as root \n"
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
void event_summary (eBPFevent* e, char* t_buffer, int t_size) {
  switch (e->etype) {
  case eTCP_ACPT:
    strncpy(t_buffer, "TCP/acpt",  t_size);
    break;
  case eTCP_CONN:
    strncpy(t_buffer, "TCP/conn",  t_size);
    break;
  case eTCP_CONN_FAIL:
    strncpy(t_buffer, "TCP/conn *fail*",  t_size);
    break;
  case eTCP_CLOSE:
    strncpy(t_buffer, "TCP/close",  t_size);
    break;
  case eTCP_RETR:
    strncpy(t_buffer, "TCP/retr",  t_size);
    break;
  case eUDP_SEND:
    strncpy(t_buffer, "UDP/send",  t_size);
    break;
  case eUDP_RECV:
    strncpy(t_buffer, "UDP/recv",  t_size);
    break;
  }
}

/* ***************************************************** */
/* ***************************************************** */

static void IPV4Handler(void* t_bpfctx, eBPFevent *e, struct ipv4_kernel_data *event) {
  char buf1[32], buf2[32];

  printf("[addr: %s:%u <-> %s:%u]",
   intoaV4(htonl(event->saddr), buf1, sizeof(buf1)), e->sport,
   intoaV4(htonl(event->daddr), buf2, sizeof(buf2)), e->dport);
}

static void IPV6Handler(void* t_bpfctx, eBPFevent *e, struct ipv6_kernel_data *event) {
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

  printf("[%s][%s][IPv4/%s][pid/tid: %u/%u [%s], uid/gid: %u/%u][father pid/tid: %u/%u [%s], uid/gid: %u/%u]",
   event.ifname, event.sent_packet ? "Sent" : "Rcvd",
   (event.proto == IPPROTO_TCP) ? "TCP" : "UDP",
   event.proc.pid, event.proc.tid,
   (event.proc.full_task_path == NULL) ? event.proc.task : event.proc.full_task_path,
   event.proc.uid, event.proc.gid,
   event.father.pid, event.father.tid,
   (event.father.full_task_path == NULL) ? event.father.task : event.father.full_task_path,
   event.father.uid, event.father.gid);

  if(event.ip_version == 4)
    IPV4Handler(t_bpfctx, &event, &event.event.v4);
  else
    IPV6Handler(t_bpfctx, &event, &event.event.v6);

  if(event.proto == IPPROTO_TCP) {
    char event_type_str[17];
    
    event_summary(&event, event_type_str, sizeof(event_type_str));

    printf("[%s]", event_type_str);
    
    if(strcmp(event_type_str, "TCP/conn") == 0)
      printf("[latency: %.2f msec]",
       ((float)event.latency_usec)/(float)1000);
  }
  
 // Container ----- /'/
  if(event.cgroup_id[0] != '\0') {
    printf("[containerID: %.12s]", event.cgroup_id);
    
    if(event.docker.dname != NULL)
      printf("[docker_name: %s]", event.docker.dname);

    if(event.kube.pod && event.kube.ns)
      printf("[kube_pod: %s][kube_ns: %s]", event.kube.pod, event.kube.ns);
  }

  printf("\n");
  ebpf_free_event(&event);
}

/* ******************************************* */

void task2json(struct taskInfo *t, struct json_object **t_res) {
  struct json_object *j = json_object_new_object();
 
  json_object_object_add(j, "pid", json_object_new_int(t->pid));
  json_object_object_add(j, "tid", json_object_new_int(t->tid));
  json_object_object_add(j, "uid", json_object_new_int(t->uid));
  json_object_object_add(j, "gid", json_object_new_int(t->gid));
  json_object_object_add(j, "task", 
    json_object_new_string(t->full_task_path != NULL ? t->full_task_path : t->task));

  *t_res = j;
}

/* ******************************************* */

void event2json(eBPFevent *t_event, struct json_object **t_res) {
  char buf1[128], buf2[128];
  char *saddr, *daddr;
  struct json_object *j = json_object_new_object(), 
    *docker_json = json_object_new_object(),
    *kube_json = json_object_new_object();
  struct json_object *proc, *father;

  json_object_object_add(j, "ktime", json_object_new_int64(t_event->ktime));
  json_object_object_add(j, "ifname", json_object_new_string(t_event->ifname));
  json_object_object_add(j, "tv_sec", json_object_new_int(t_event->event_time.tv_sec));
  json_object_object_add(j, "tc_usec", json_object_new_int(t_event->event_time.tv_usec));
  json_object_object_add(j, "ip_version", json_object_new_int(t_event->ip_version));
  json_object_object_add(j, "etype", json_object_new_int(t_event->etype));
  json_object_object_add(j, "sent_packet", json_object_new_int(t_event->sent_packet));

  if(t_event->ip_version == 4) {
    saddr = intoaV4(htonl(t_event->event.v4.saddr), buf1, sizeof(buf1));
    daddr = intoaV4(htonl(t_event->event.v4.daddr), buf2, sizeof(buf2));
  } else {
    saddr = intoaV6(&t_event->event.v6.saddr, buf1, sizeof(buf1));
    daddr = intoaV6(&t_event->event.v6.daddr, buf2, sizeof(buf2));
  }
  json_object_object_add(j, "saddr", json_object_new_string(saddr));
  json_object_object_add(j, "daddr", json_object_new_string(daddr));
 
  json_object_object_add(j, "proto", json_object_new_int(t_event->proto));
  json_object_object_add(j, "sport", json_object_new_int(t_event->sport));
  json_object_object_add(j, "dport", json_object_new_int(t_event->dport));
  json_object_object_add(j, "latency_usec", json_object_new_int(t_event->latency_usec));
  json_object_object_add(j, "retransmissions", json_object_new_int(t_event->retransmissions));

  task2json(&t_event->proc, &proc);
  json_object_object_add(j, "proc", proc);
  task2json(&t_event->father, &father);
  json_object_object_add(j, "father", father);

  if(t_event->cgroup_id[0] != '\0')
    json_object_object_add(j, "cgroup_id", json_object_new_string(t_event->cgroup_id));
  if(t_event->docker.dname != NULL) {
    docker_json = json_object_new_object();
    json_object_object_add(docker_json, "dname", json_object_new_string(t_event->docker.dname));
    json_object_object_add(j, "docker", docker_json);
  }
  if(t_event->kube.pod) { 
    kube_json = json_object_new_object();
    json_object_object_add(kube_json, "pod", json_object_new_int(t_event->retransmissions));
    json_object_object_add(kube_json, "ns", json_object_new_int(t_event->retransmissions));
    json_object_object_add(j, "kube", kube_json);
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

  // writing event ----- //
  struct zmq_msg_hdr msg_hdr;
  strncpy(msg_hdr.url, "ebpfflow", sizeof(msg_hdr.url));
  msg_hdr.version = 0;
  msg_hdr.size = strlen(json_str);
  zmq_send(gZMQsocket, &msg_hdr, sizeof(msg_hdr), ZMQ_SNDMORE);
  zmq_send(gZMQsocket, json_str, msg_hdr.size, 0);

  json_object_put(json_event);
  ebpf_free_event(&event);
}  

/* ******************************************* */

static void handleTermination(int t_s) {
  if(!gRUNNING) return;

  printf("\r* Terminating * \n");
  gRUNNING = 0;
}
