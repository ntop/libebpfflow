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

/* 
 * This package implements an interface to capture network events
 * by using eBPF probes attached to Linux kernel functions.
 * Note: only one event handler at a time is supported
 */
package goebpf_flow

import (
    "fmt"
    "net"
    "encoding/binary"
    "unsafe"
)

/* 
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L.. -lebpfflow -lcurl -lbcc -ljson-c -lstdc++
#include "../ebpf_flow.h"

#include <stdlib.h>

void go_handleEvent(void *t_bpfctx, void *t_data, int t_datalen);

static void* wrapper_init_ebpf_flow(__u16 flags) {
  ebpfRetCode rc;
  return init_ebpf_flow(NULL, go_handleEvent, &rc, flags);
}

static eBPFevent* preprocess(eBPFevent *e) {  
  eBPFevent *event = malloc(sizeof(eBPFevent));
  memcpy(event, e, sizeof(eBPFevent));
  ebpf_preprocess_event(event);
  return event;
}
*/
import "C"


/* ****************************************** */
// ===== ===== KERNEL->USER EVENT ===== ===== //
/* ****************************************** */
const COMMAND_LEN = 16 // defined in sched.h
const IFNAMSIZ = 16 // max is in limits.h -> NAME_MAX
const CGROUP_ID_LEN = 64

/*
 * Events types are forged as follows:
 *  I_digit (=1): init events (e.g. connection creation)
 *          (=2): update events on existing connection
 *          (=3): connection closing
 *          (=5): operation failed
 *  II_digit (=0): tcp events
 *           (=1): udp events
 *  III_digit: discriminate the single event
 * The type is reported in eEBPFevent->etype
 */
type etype uint32
const (
  eTCP_ACPT = 100
  eTCP_CONN = 101
  eTCP_CONN_FAIL = 500
  eUDP_RECV = 210
  eUDP_SEND = 211
  eTCP_RETR = 200
  eTCP_CLOSE = 300
)

/*
 * Supported flags to filter events when initializating libebpfflow
 * Combinations of this flags allow to capture only subsets of events
 */
type libebpflow_flag uint16
const (
  LIBEBPF_TCP = 1 << 0
  LIBEBPF_UDP = 1 << 1
  LIBEBPF_INCOMING = 1 << 2
  LIBEBPF_OUTCOMING = 1 << 3
  LIBEBPF_TCP_CLOSE = 1 << 4
  LIBEBPF_TCP_RETR = 1 << 5
)

type TaskInfo struct {
  Pid uint32
  Uid uint32
  Gid uint32
  Task string // task name
  Full_Task_Path string
}

type DockerInfo struct {
  Name string // Docker container name
}

type KubeInfo struct {
  Name string // Container name
  Pod string // Container pod
  Ns string // Kubernetes namespace
}

type EBPFevent struct {
  Ktime uint64 // Absolute kernel time
  Ifname string // net-dev name
  Event_time uint64 // Event time, filled during event preprocessing
  Ip_version uint8
  Sent_packet uint8
  EType etype // event type, supported events are listed in event_type enum

  Saddr net.IP
  Daddr net.IP

  Proto uint8
  Sport, Dport uint16
  Latency_usec uint32
  Retransmissions uint16

  Proc TaskInfo
  Father TaskInfo

  Container_id string // Container identifier
  // Both next fields are initializated to nil and populated only during preprocessing
  Docker *DockerInfo
  Kube *KubeInfo
}

/*
 * Implements the methods to manage eBPF events. The correct usage requires:
 *    1. Initialization with NewEbpflow 
 *    2. Event polling by using the funcion PollEvent
 *    3. Invocation of Term to clean resources
 */
type Ebpflow struct {
  ebpf unsafe.Pointer
}

var gHandler func(EBPFevent)

/*
 * Creates a new Ebpflow object from which start capuring events
 * Args: 
 *    handler - function handler, called whenever a new event is captured
 *              and the function Poll is invoked
 *    flags - filter the events based on which bits are active. If the value
 *            is zero all events are captured. Check libebpflow_flag for more details
 */
func NewEbpflow (handler func(EBPFevent), flags uint16) *Ebpflow {
  ebpfp, _ := C.wrapper_init_ebpf_flow(0)
  if ebpfp == nil {
    fmt.Println("Error, unable to initialize libebpfflow")
    return nil
  }

  gHandler = handler
  return &Ebpflow{ ebpf: ebpfp }
}

/*
 * Frees the resources used
 */
func (e Ebpflow) Close () {
  C.term_ebpf_flow(e.ebpf);
}

/*
 * If a new event has been capured the handler provided on creation is 
 * invoked with the new event as argument.
 * Args:
 *      timeout - waits at most timeout milliseconds if no new event is captured
 */
func (e Ebpflow) PollEvent(timeout int) {
  C.ebpf_poll_event(e.ebpf, (C.uint)(timeout))
}

/*
 * Translates information concerning a task from a C structure to a Go struct
 */
func c2TaskInfo (p C.struct_taskInfo) TaskInfo {
  return TaskInfo {
    Pid: (uint32)(p.pid),
    Uid: (uint32)(p.uid),
    Gid: (uint32)(p.gid),
    Task: C.GoString(&p.task[0]),
    Full_Task_Path: C.GoString(p.full_task_path),
  }
}

//export go_handleEvent
func go_handleEvent(t_bpfctx unsafe.Pointer, t_data unsafe.Pointer, t_datalen C.int) {
  event := (* C.eBPFevent)(t_data)
  filled_event := C.preprocess(event);

  goevent := EBPFevent {
    Ktime: (uint64)(filled_event.ktime),
    Ifname: C.GoString(&filled_event.ifname[0]),
    Proto: (uint8)(filled_event.proto),
    Latency_usec: (uint32)(filled_event.latency_usec),
    Retransmissions: (uint16)(filled_event.retransmissions),
    Ip_version: (uint8)(filled_event.ip_version),
    Sent_packet: (uint8)(filled_event.sent_packet),
    Sport: (uint16)(filled_event.sport),
    Dport: (uint16)(filled_event.dport),
    Proc: c2TaskInfo(filled_event.proc),
    Father: c2TaskInfo(filled_event.father),
    Container_id: C.GoString(&filled_event.container_id[0]),
  }
  if(filled_event.ip_version == 4) {
    ipv4 := (*C.struct_ipv4_addr_t)(unsafe.Pointer(&filled_event.addr[0]))
    goevent.Saddr = make(net.IP, 4)
    binary.LittleEndian.PutUint32(goevent.Saddr, (uint32)(ipv4.saddr))
    goevent.Daddr = make(net.IP, 4)
    binary.LittleEndian.PutUint32(goevent.Daddr, (uint32)(ipv4.daddr))
  } else {
    ipv6 := (*C.struct_ipv6_addr_t)(unsafe.Pointer(&filled_event.addr[0]))
    saddr := ([16]byte)(ipv6.saddr)
    goevent.Saddr = net.ParseIP(string(saddr[:]))
    daddr := ([16]byte)(ipv6.daddr)
    goevent.Daddr = net.ParseIP(string(daddr[:]))
  }

  if(filled_event.docker.name != nil) {
    goevent.Docker = &DockerInfo {
      Name: C.GoString(filled_event.docker.name),
    }
  } else {
    goevent.Docker = nil
  }

  if(filled_event.kube.pod != nil) {
    goevent.Kube = &KubeInfo {
      Name: C.GoString(filled_event.kube.name),
      Pod: C.GoString(filled_event.kube.pod),
      Ns: C.GoString(filled_event.kube.ns),
    }
  } else {
    goevent.Kube = nil
  }

  gHandler(goevent)
  C.ebpf_free_event(filled_event)
}





