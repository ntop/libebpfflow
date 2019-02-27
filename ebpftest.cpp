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
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>

#include "ebpf_flow.h"

/* ****************************************************** */

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

/* ****************************************************** */

static char* intoaV6(void *addr, char* buf, u_short bufLen) {
  char *ret = (char*)inet_ntop(AF_INET6, addr, buf, bufLen);

  if(ret == NULL)
    buf[0] = '\0';

  return(buf);
}

/* ***************************************************** */

static void IPV4Handler(void* t_bpfctx, eBPFevent *e, struct ipv4_kernel_data *event) {
  char buf1[32], buf2[32];

  printf("[%s][%s][IPv4/%s][pid/tid: %u/%u [%s], uid/gid: %u/%u][father pid/tid: %u/%u [%s], uid/gid: %u/%u][addr: %s:%u <-> %s:%u]",
	 e->ifname, e->sent_packet ? "Sent" : "Rcvd",
	 (event->net.proto == IPPROTO_TCP) ? "TCP" : "UDP",
	 e->proc.pid, e->proc.tid,
	 (e->proc.full_task_path == NULL) ? e->proc.task : e->proc.full_task_path,
	 e->proc.uid, e->proc.gid,
	 e->father.pid, e->father.tid,
	 (e->father.full_task_path == NULL) ? e->father.task : e->father.full_task_path,
	 e->father.uid, e->father.gid,
	 intoaV4(htonl(event->saddr), buf1, sizeof(buf1)), event->net.sport,
	 intoaV4(htonl(event->daddr), buf2, sizeof(buf2)), event->net.dport);

  if (e->docker != NULL) printf("[docker: %s/%s]", e->cgroup_id, e->docker->dname);
  if (e->kube !=  NULL) printf("[kube pod/ns: %s/%s]", e->kube->pod, e->kube->ns);

  if(event->net.proto == IPPROTO_TCP)
    printf("[latency: %.2f msec]", ((float)event->net.latency_usec)/(float)1000);
}

/* ***************************************************** */

static void IPV6Handler(void* t_bpfctx, eBPFevent *e, struct ipv6_kernel_data *event) {
  char buf1[32], buf2[32];
  unsigned long long high = (event->saddr >> 64) &0xFFFFFFFFFFFFFFFF;
  unsigned long long low = event->saddr & 0xFFFFFFFFFFFFFFFF;

  printf("[%s][%s][IPv6/%s][pid/tid: %u/%u (%s [%s]), uid/gid: %u/%u][father pid/tid: %u/%u (%s [%s]), uid/gid: %u/%u][addr: %s:%u <-> %s:%u]",
	 e->ifname, e->sent_packet ? "S" : "R",
	 (event->net.proto == IPPROTO_TCP) ? "TCP" : "UDP", e->proc.pid, e->proc.tid,
	 e->proc.task, (e->proc.full_task_path == NULL) ? e->proc.task : e->proc.full_task_path,
	 e->proc.uid, e->proc.gid,
	 e->father.pid, e->father.tid,
	 e->proc.task, (e->father.full_task_path == NULL) ? e->father.task : e->father.full_task_path,
	 e->father.uid, e->father.gid,
	 intoaV6(&event->saddr, buf1, sizeof(buf1)),
	 event->net.sport,
	 intoaV6(&event->daddr, buf2, sizeof(buf2)),
	 event->net.dport);

  if (e->docker != NULL) printf("[docker: %s/%s]", e->cgroup_id, e->docker->dname);
  if (e->kube != NULL) printf("[kube pod/ns: %s/%s]", e->kube->pod, e->kube->ns);

  if(event->net.proto == IPPROTO_TCP)
    printf("[latency: %.2f msec]", ((float)event->net.latency_usec)/(float)1000);
}

/* ***************************************************** */

static void ebpfHandler(void* t_bpfctx, void* t_data, int t_datasize) {
  eBPFevent *e = (eBPFevent*)t_data;
  eBPFevent event;
  struct timespec tp;

  memcpy(&event, e, sizeof(eBPFevent)); /* Copy needed as ebpf_preprocess_event will modify the memory */

  ebpf_preprocess_event(&event, true);

  clock_gettime(CLOCK_MONOTONIC, &tp);

#if 0
  printf("[latency %.1f usec] ",
	 (float)(tp.tv_nsec-(event.ktime % 1000000000))/(float)1000);
#endif

  printf("%u.%06u ",
	 (unsigned int)event.event_time.tv_sec,
	 (unsigned int)event.event_time.tv_usec);
  
  if(event.ip_version == 4)
    IPV4Handler(t_bpfctx, &event, &event.event.v4);
  else
    IPV6Handler(t_bpfctx, &event, &event.event.v6);

  printf("\n");
  ebpf_free_event(&event);
}

/* ***************************************************** */

int main(int argc, char *argv[]) {
  ebpfRetCode rc;
  void *ebpf;

  if(getuid() != 0) {
    printf("You need root capabilities to run this tool\n");
    return(-1);
  }

  printf("Welcome to libebpfflow v.%s\n(C) 2018-19 ntop.org\n", 
	 ebpf_flow_version());
  
  printf("Initializing eBPF [%s]...\n",
#ifdef NEW_EBF
	 "New API"
#else
	 "Legacy API"
#endif
	 );
  ebpf = init_ebpf_flow(NULL, ebpfHandler, &rc);

  if(!ebpf) {
    printf("Unable to initialize libebpfflow: %s\n", ebpf_print_error(rc));
    return(rc);
  }

  printf("eBPF initializated successfully\n");

  while(true)
    ebpf_poll_event(ebpf, 10);

  term_ebpf_flow(ebpf);
  printf("eBPF terminated\n");

  return(0);
}
