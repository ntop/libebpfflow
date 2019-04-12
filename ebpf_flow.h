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

#define COMMAND_LEN       16
#define CGROUP_ID_LEN     65

/*
 * Events types are forged as follows:
 *  I_digit (=1): init events (e.g. connection creation)
 *          (=2): update events on existing connection
 *          (=3): connection closing
 *          (=5): operation failed
 *  II_digit (=0): tcp events
 *           (=1): udp events
 *  III_digit: discriminate the single event
 * The type is reported in eBPFevent->etype
 */
typedef enum {
  eTCP_ACPT = 100,
  eTCP_CONN = 101,
  eTCP_CONN_FAIL = 500,
  eUDP_RECV = 210,
  eUDP_SEND = 211,
  eTCP_RETR = 200,
  eTCP_CLOSE = 300,
} event_type;

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
};

struct ipv6_kernel_data {
  unsigned __int128 saddr;
  unsigned __int128 daddr;  
};

struct dockerInfo {
  char dname[100]; // Docker container name
};

struct kubeInfo {
  char pod[60];
  char ns[60]; // Kubernetes namespace
};

typedef struct {
  __u64 ktime; // Absolute kernel time
  char ifname[IFNAMSIZ]; // net-dev name
  struct timeval event_time; // Event time, filled during event preprocessing
  __u8  ip_version, sent_packet;
  __u16 etype; // event type, supported events are listed in event_type enum
  
  union {
    struct ipv4_kernel_data v4;
    struct ipv6_kernel_data v6;
  } event;

  __u8  proto;
  __u16 sport, dport;
  __u32 latency_usec;
  __u16 retransmissions;

  struct taskInfo proc, father;

  char cgroup_id[CGROUP_ID_LEN]; // Container identifier
  // Both next fields are initializated to NULL and populated only during preprocessing
  char *runtime;
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

/*
 * Supported flags to filter events when initializating libebpfflow
 * Combinations of this flags allow to capture only subsets of events
 */
typedef enum {
  LIBEBPF_TCP = 1 << 0,
  LIBEBPF_UDP = 1 << 1,
  LIBEBPF_INCOMING = 1 << 2,
  LIBEBPF_OUTCOMING = 1 << 3,
  LIBEBPF_TCP_CLOSE = 1 << 4,
  LIBEBPF_TCP_RETR = 1 << 5,
} libebpflow_flag;


/* ******************************************* */

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

  typedef void (*eBPFHandler)(void* t_bpfctx, void* t_data, int t_datasize);
 
  /*
   * init_ebpf_flow - Initializes the library with a target event handler
   * @ebpfHandler: the function used to handle events
   * @rc: pointer to the variable in which to store the return code
   * @flags: restrict the number of events to generate by
   *    not tracing certain functions. Use default (i.e. 0 or 0xFFFF) to capture
   *    all events. Supported events are combinations of libebpflow_flag enum type
   * returns a pointer to an ebpf::BPF object upon success NULL otherwise
   */
  void* init_ebpf_flow(void *priv_ptr, eBPFHandler ebpfHandler, 
		       ebpfRetCode *rc, u_int16_t flags /* default 0 to capture all events */);

  /*
   * term_ebpf_flow - Cleans the resources used by the library
   * @ebpfHook: a pointer to an ebpf::BPF, that is the one returned by init_ebpf_flow 
   */  
  void term_ebpf_flow(void *ebpfHook);
  
  /*
   * ebpf_poll_event: Pools an event from an ebpf::BPF object
   * @ms_timeout: maximum time to wait for an event
   * @ebpfHook: reference to the result of init_ebpf_flow invocation
   * return 1 if an event has been processed, 0 in case of timeout.
   */
  int ebpf_poll_event(void *ebpfHook, u_int ms_timeout);
  
  /*
   * Collect further information wrt the one contained in an eBPF event
   * @docker_flag: if 1 docker daemon will be queried to gather information
   *    concerning containers
   * @runtime: container runtime, NULL to inspect both 'containerd' and 'docker'
   */
  void ebpf_preprocess_event(eBPFevent *event, int docker_flag, char* runtime);

  const char* ebpf_print_error(ebpfRetCode rc);

  /*
  * Cleans the resources used by an eBPFevent data structure
  */
  void ebpf_free_event(eBPFevent *event);
  const char* ebpf_flow_version();
  
#ifdef __cplusplus
};
#endif // __cplusplus

#endif /* __EBPF_FLOW_H__ */
