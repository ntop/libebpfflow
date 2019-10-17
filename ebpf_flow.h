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

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/types.h>
#include <linux/if.h>
#endif
#include <string.h>

#define ktime_t u_int64_t
#define u8 u_int8_t
#define u16 u_int16_t
#define u32 u_int32_t
#define u64 u_int64_t

#include "ebpf_types.h"

/* ******************************************* */

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
 * Combinations of this flags allow selecte events to be to captured
 */
typedef enum {
  LIBEBPF_TCP       = 1 << 0,
  LIBEBPF_UDP       = 1 << 1,
  LIBEBPF_INCOMING  = 1 << 2,
  LIBEBPF_OUTCOMING = 1 << 3,
  LIBEBPF_TCP_CLOSE = 1 << 4,
  LIBEBPF_TCP_RETR  = 1 << 5,
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
		       ebpfRetCode *rc,
		       u_int16_t flags /* default 0 to capture all events */);

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
   */
  void ebpf_preprocess_event(eBPFevent *event);

  const char* ebpf_print_error(ebpfRetCode rc);

  /*
  * Cleans the resources used by an eBPFevent data structure
  */
  void ebpf_free_event(eBPFevent *event);


  /* ******************************************* */
  /*
   * Returns the handler used by this library to retrieve container information
   * to be casted to ContainerInfo* to avoid mixinc C with C++
   */
  void* ebpf_get_cinfo_handler();

  const char* ebpf_flow_version();

#ifdef __cplusplus
};
#endif // __cplusplus

#endif /* __EBPF_FLOW_H__ */
