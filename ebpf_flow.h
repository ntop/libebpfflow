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

#ifndef __EBPF_FLOW_H__
#define __EBPF_FLOW_H__ 1

#include <unistd.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/if.h>
#include <string.h>

/* ******************************************* */

#define EBPF_FLOW_VERSION "1.0.190213"

#define HAVE_NEW_EBPF

#define COMMAND_LEN       16
#define CGROUP_ID_LEN     64

struct netInfo {
  __u16 sport;
  __u16 dport;
  __u8  proto;
  __u32 latency_usec;
};

struct taskInfo {
  __u32 pid; /* Process Id */
  __u32 tid; /* Thread Id  */
  __u32 uid; /* User Id    */
  __u32 gid; /* Group Id   */
  char task[COMMAND_LEN], *full_task_path;
};
  
// ----- ----- STRUCTS AND CLASSES ----- ----- //
struct ipv4_kernel_data {
  __u64 saddr;
  __u64 daddr;
  struct netInfo net;
};

struct ipv6_kernel_data {
  unsigned __int128 saddr;
  unsigned __int128 daddr;
  struct netInfo net;
};

struct dockerInfo {
  char dname[100];
};

struct kubeInfo {
  char pod[60];
  char ns[60];
};

typedef struct {
  __u64 ktime;
  char ifname[IFNAMSIZ];
  struct timeval event_time;
  __u8  ip_version:4, sent_packet:4;
  
  union {
    struct ipv4_kernel_data v4;
    struct ipv6_kernel_data v6;
  } event;

  struct taskInfo proc, father;

  char cgroup_id[CGROUP_ID_LEN];
  struct dockerInfo *docker;
  struct kubeInfo *kube;
} eBPFevent;

typedef enum {
  ebpf_no_error = 0,
  ebpf_initialization_failed,
  ebpf_unable_to_load_kernel_probe,
  ebpf_out_of_memory,
  ebpf_kprobe_attach_error,
  ebpf_events_open_error,
} ebpfRetCode;

typedef enum {
  TCP = 1 << 0,
  UDP = 1 << 1,
  INCOME = 1 << 2,
  OUTCOME = 1 << 3,
} libebpflow_flag;


/* ******************************************* */

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  typedef void (*eBPFHandler)(void* t_bpfctx, void* t_data, int t_datasize);
  
  void* init_ebpf_flow(void *priv_ptr, eBPFHandler ebpfHandler, ebpfRetCode *rc, short flags=0xffff);
  void  term_ebpf_flow(void *ebpfHook);
  void  ebpf_poll_event(void *ebpfHook, u_int ms_timeout);
  void ebpf_preprocess_event(eBPFevent *event, int docker_flag);
  const char* ebpf_print_error(ebpfRetCode rc);
  void ebpf_free_event(eBPFevent *event);
  const char* ebpf_flow_version();
  
#ifdef __cplusplus
};
#endif // __cplusplus

#endif /* __EBPF_FLOW_H__ */
