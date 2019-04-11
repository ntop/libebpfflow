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

#include "ebpf_flow.h"


using namespace std;

int gDOCKER_ENABLE=1;
int gRUNNING = 1;

void help();
static char* intoaV4(unsigned int addr, char* buf, u_short bufLen);
char* intoaV6(unsigned __int128 addr, char* buf, u_short bufLen);
void event_summary (eBPFevent* e, char* t_buffer, int t_size);
static void handleTermination(int t_s=0);
static void verboseHandleEvent(void* t_bpfctx, void* t_data, int t_datasize);
static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize);

/* **************************** */
// ===== ===== MAIN ===== ===== //
/* **************************** */

static const struct option long_opts[] = {
  { "retr", 0, NULL, 'r' },
  { "tcpclose", 0, NULL, 'c' },
  { "udp", 0, NULL, 'u' },
  { "tcp", 0, NULL, 't' },
  { "in", 0, 0, 'i' },
  { "out", 0, 0, 'o' },
  { "docker", 0, NULL, 'd' },
  { "help", 0, NULL, 'h' },
  { "verbose", 0, 0, 'v' },
  { NULL, 0, NULL, 0 }
};

int main(int argc, char **argv) {
  int ch;
  short flags = 0;
  ebpfRetCode rc;
  void *ebpf;
  void (*handler)(void*, void*, int) = ebpfHandler;

  signal(SIGINT, handleTermination);

  // Argument Parsing ----- //
  gDOCKER_ENABLE=1;
  while ((ch = getopt_long(argc, argv, "rcutiodvh", long_opts, NULL)) != EOF) {
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
    case 'd':
      gDOCKER_ENABLE=1;
      break;
    case 'v':
      handler = verboseHandleEvent;
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
    return(rc);
  }

  printf("eBPF initializated successfully\n");

  // Polling event ----- //
  while(gRUNNING) {
    ebpf_poll_event(ebpf, 10);
  }

  // Cleaning and terminating ----- //
  term_ebpf_flow(ebpf);
  printf("eBPF terminated\n");
}

void help() {
  printf(
	 "toolebpflow: Traffic visibility tool based on libebpfflow. By default all events will be shown \n"
	 "Termination: CTRL-C \n"
	 "Usage: ebpflow [ OPTIONS ] \n"
	 "   -h, --help      display this message \n"
	 "   -t, --tcp       TCP events \n"
	 "   -u, --udp       UDP events \n"
	 "   -i, --in        incoming events (i.e. TCP accept and UDP receive) \n"
	 "   -o, --on        outgoing events (i.e. TCP connect and UDP send) \n"
	 "   -r, --retr      retransmissions events \n"
	 "   -c, --tcpclose  TCP close events \n"
	 "   -d, --docker    gather additional information concerning containers  (default: enabled)\n"
	 "   -v, --verbose   vebose formatting"
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

static void verboseHandleEvent(void* t_bpfctx, void* t_data, int t_datasize) {
  char event_type_str[17];
  struct ipv4_kernel_data *ipv4_event;
  struct ipv6_kernel_data *ipv6_event;
  eBPFevent *e = (eBPFevent*)t_data;
  eBPFevent event;

  // Preprocessing event ----- //
  // Copy needed as ebpf_preprocess_event will modify the memory
  memcpy(&event, e, sizeof(eBPFevent));
  ebpf_preprocess_event(&event, gDOCKER_ENABLE, NULL);

  // Event info ----- //
  printf("[%u.%06u]",
	 (unsigned int)event.event_time.tv_sec,
	 (unsigned int)event.event_time.tv_usec);

  // Task ----- //
  printf("[pid: %lu][uid: %lu][gid: %lu][%s] \n",
	 (long unsigned int)event.proc.gid,
	 (long unsigned int)event.proc.uid,
	 (long unsigned int)event.proc.pid,
	 event.proc.task);

  // Parent ----- //
  printf("\t [parent][pid: %lu][uid: %lu][gid: %lu][%s]\n",
	 (long unsigned int)event.father.gid,
	 (long unsigned int)event.father.uid,
	 (long unsigned int)event.father.pid,
	 event.father.task);

  // Network basic ----- //
  event_summary(&event, event_type_str, sizeof(event_type_str));
  if(event.ip_version == 4) {
    // IPv4 Event type
    ipv4_event = &event.event.v4;
    // IPv4 Network info
    char buf1[32], buf2[32];

    printf("\t [%s][IPv%d][%s][addr: %s:%d <-> %s:%d]\n",
	   event.ifname,
	   event.ip_version,
	   event_type_str,
	   intoaV4(htonl(ipv4_event->saddr), buf1, sizeof(buf1)), event.sport,
	   intoaV4(htonl(ipv4_event->daddr), buf2, sizeof(buf2)), event.dport);
    // IPv4 Latency if available
    if(strcmp(event_type_str, "TCP/conn") == 0) {
      printf("\t [latency: %.2f msec] \n",
	     ((float)event.latency_usec)/(float)1000);
    }
  }
  else {
    // IPv6 Event type
    struct ipv6_kernel_data *ipv6_event = &event.event.v6;
    // IPv6 Network info
    char buf1[128], buf2[128];

    printf("\t [%s][IPv%d][%s][addr: %s:%d <-> %s:%d] \n",
	   event.ifname,
	   event.ip_version,
	   event_type_str,
	   intoaV6(&ipv6_event->saddr, buf1, sizeof(buf1)), event.sport,
	   intoaV6(&ipv6_event->saddr, buf2, sizeof(buf2)), event.dport);
    // IPv6 Latency if available
    if(strcmp(event_type_str, "TCP/conn") == 0)
      printf("\t [latency: %.2f msec] \n",
	     ((float)event.latency_usec)/(float)1000);
  }

  // Container ----- //
  if(event.runtime!=NULL && event.runtime[0] != '\0') /* Setted if info are available */ {
    printf("\t [containerID: %.12s][runtime: %s]", event.cgroup_id, event.runtime);

    if(event.docker != NULL)
      printf("[docker_name: %s]", event.docker->dname);
    if(event.kube != NULL)
      printf("[kube_pod: %s][kube_ns: %s]", event.kube->pod, event.kube->ns);
    printf("\n");
  }

  ebpf_free_event(&event);
}

/* ***************************************************** */
/* ***************************************************** */

static void IPV4Handler(void* t_bpfctx, eBPFevent *e, struct ipv4_kernel_data *event) {
  char buf1[32], buf2[32];

  printf("[%s][%s][IPv4/%s][pid/tid: %u/%u [%s], uid/gid: %u/%u][father pid/tid: %u/%u [%s], uid/gid: %u/%u][addr: %s:%u <-> %s:%u]",
	 e->ifname, e->sent_packet ? "Sent" : "Rcvd",
	 (e->proto == IPPROTO_TCP) ? "TCP" : "UDP",
	 e->proc.pid, e->proc.tid,
	 (e->proc.full_task_path == NULL) ? e->proc.task : e->proc.full_task_path,
	 e->proc.uid, e->proc.gid,
	 e->father.pid, e->father.tid,
	 (e->father.full_task_path == NULL) ? e->father.task : e->father.full_task_path,
	 e->father.uid, e->father.gid,
	 intoaV4(htonl(event->saddr), buf1, sizeof(buf1)), e->sport,
	 intoaV4(htonl(event->daddr), buf2, sizeof(buf2)), e->dport);

  if(e->runtime!=NULL && e->runtime[0] != '\0') /* Setted if info are available */ {
    printf("[containerID: %.12s][runtime: %s]", e->cgroup_id, e->runtime);

    if(e->docker != NULL)
      printf("[docker_name: %s]", e->docker->dname);
    if(e->kube != NULL)
      printf("[kube_pod: %s][kube_ns: %s]", e->kube->pod, e->kube->ns);
  }

  if(e->proto == IPPROTO_TCP)
    printf("[latency: %.2f msec]", ((float)e->latency_usec)/(float)1000);
}


static void IPV6Handler(void* t_bpfctx, eBPFevent *e, struct ipv6_kernel_data *event) {
  char buf1[32], buf2[32];
  unsigned long long high = (event->saddr >> 64) &0xFFFFFFFFFFFFFFFF;
  unsigned long long low = event->saddr & 0xFFFFFFFFFFFFFFFF;

  printf("[%s][%s][IPv6/%s][pid/tid: %u/%u (%s [%s]), uid/gid: %u/%u][father pid/tid: %u/%u (%s [%s]), uid/gid: %u/%u][addr: %s:%u <-> %s:%u]",
	 e->ifname, e->sent_packet ? "S" : "R",
	 (e->proto == IPPROTO_TCP) ? "TCP" : "UDP", e->proc.pid, e->proc.tid,
	 e->proc.task, (e->proc.full_task_path == NULL) ? e->proc.task : e->proc.full_task_path,
	 e->proc.uid, e->proc.gid,
	 e->father.pid, e->father.tid,
	 e->proc.task, (e->father.full_task_path == NULL) ? e->father.task : e->father.full_task_path,
	 e->father.uid, e->father.gid,
	 intoaV6(&event->saddr, buf1, sizeof(buf1)),
	 e->sport,
	 intoaV6(&event->daddr, buf2, sizeof(buf2)),
	 e->dport);

  // Container ----- //
  if(e->runtime!=NULL && e->runtime[0] != '\0') /* Setted if info are available */ {
    printf("[containerID: %.12s][runtime: %s]", e->cgroup_id, e->runtime);

    if(e->docker != NULL)
      printf("[docker_name: %s]", e->docker->dname);
    if(e->kube != NULL)
      printf("[kube_pod: %s][kube_ns: %s]", e->kube->pod, e->kube->ns);
  }

  if(e->proto == IPPROTO_TCP)
    printf("[latency: %.2f msec]", ((float)e->latency_usec)/(float)1000);
}


static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize) {
  eBPFevent *e = (eBPFevent*)t_data;
  eBPFevent event;
  struct timespec tp;

  memcpy(&event, e, sizeof(eBPFevent)); /* Copy needed as ebpf_preprocess_event will modify the memory */

  ebpf_preprocess_event(&event, 1, NULL);

  clock_gettime(CLOCK_MONOTONIC, &tp);

#if 0
  printf("[latency %.1f usec] ",
	 (float)(tp.tv_nsec-(event.ktime % 1000000000))/(float)1000);
#endif

  printf("%u.%06u ", (unsigned int)event.event_time.tv_sec, (unsigned int)event.event_time.tv_usec);

  if(event.ip_version == 4)
    IPV4Handler(t_bpfctx, &event, &event.event.v4);
  else
    IPV6Handler(t_bpfctx, &event, &event.event.v6);

  printf("\n");
  ebpf_free_event(&event);
}


static void handleTermination(int t_s) {
  if(!gRUNNING) return;

  printf("\r* Terminating * \n");
  gRUNNING = 0;
}
