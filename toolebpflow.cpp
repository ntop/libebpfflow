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

void help();
static char* intoaV4(unsigned int addr, char* buf, u_short bufLen);
char* intoaV6(unsigned __int128 addr, char* buf, u_short bufLen);
void event_summary (eBPFevent* e, char* t_buffer, int t_size);
static void handleTermination(int t_s=0);
static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize);
static int  gRUNNING = 1;

/* **************************** */
// ===== ===== MAIN ===== ===== //
/* **************************** */

static const struct option long_opts[] = {
  { "retr",     0, NULL, 'r' },
  { "tcpclose", 0, NULL, 'c' },
  { "udp",      0, NULL, 'u' },
  { "tcp",      0, NULL, 't' },
  { "in",       0, NULL, 'i' },
  { "out",      0, NULL, 'o' },
  { "docker",   0, NULL, 'd' },
  { "help",     0, NULL, 'h' },
  { NULL,       0, NULL,  0  }
};

int main(int argc, char **argv) {
  int ch;
  short flags = 0;
  ebpfRetCode rc;
  void *ebpf;

  signal(SIGINT, handleTermination);

  // Argument Parsing ----- //

  while ((ch = getopt_long(argc, argv, "rcutioh", long_opts, NULL)) != EOF) {
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
  ebpf = init_ebpf_flow(NULL, ebpfHandler, &rc, flags);
  
  if(!ebpf) {
    printf("Unable to initialize libebpfflow: %s\n", ebpf_print_error(rc));
    return(rc);
  }

  printf("eBPF initializated successfully\n");

  // Polling event ----- //
  while(gRUNNING)
    ebpf_poll_event(ebpf, 10);  

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

/* ***************************************************** */
/* ***************************************************** */

static void IPV4Handler(void* t_bpfctx, eBPFevent *e, struct ipv4_kernel_data *event) {
  char buf1[32], buf2[32];

  printf("[addr: %s:%u <-> %s:%u]",
	 intoaV4(htonl(event->saddr), buf1, sizeof(buf1)), e->sport,
	 intoaV4(htonl(event->daddr), buf2, sizeof(buf2)), e->dport);
}

static void IPV6Handler(void* t_bpfctx, eBPFevent *e, struct ipv6_kernel_data *event) {
  char buf1[32], buf2[32];

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


static void handleTermination(int t_s) {
  if(!gRUNNING) return;

  printf("\r* Terminating * \n");
  gRUNNING = 0;
}
