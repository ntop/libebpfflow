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

static void* init (__u16 flags) {
  ebpfRetCode rc;
  return init_ebpf_flow(NULL, go_handleEvent, &rc, flags);
}

static eBPFevent* preprocess (eBPFevent *e) {  
  eBPFevent *event = malloc(sizeof(eBPFevent));
  memcpy(event, e, sizeof(eBPFevent));
  ebpf_preprocess_event(event, 1);
  return event;
}
*/
import "C"


/* ****************************************** */
// ===== ===== KERNEL->USER EVENT ===== ===== //
/* ****************************************** */
const COMMAND_LEN = 16
const IFNAMSIZ = 16
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
 * The type is reported in eBPFevent->etype
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

type TaskInfo struct {
  Pid uint32
  Uid uint32
  Gid uint32
  Task string // task name
  Full_Task_Path string
}

type DockerInfo struct {
  Dname string // Docker container name
}

type KubeInfo struct {
  Pod string
  Ns string // Kubernetes namespace
}

type BPFevent struct {
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

  Cgroup_id string // Docker identifier
  // Both next fields are initializated to NULL and populated only during preprocessing
  Docker *DockerInfo
  Kube *KubeInfo
}

type Ebpflow struct {
  ebpf unsafe.Pointer
}

var gHandler func(BPFevent)

func NewEbppflow (handler func(BPFevent)) *Ebpflow {
  res, _ := C.ebpf_flow_version()
  fmt.Println("Invoking c library... \n", C.GoString(res))

  // Initialization
  ebpfp, _ := C.init(0)
  if ebpfp == nil {
    fmt.Println("Error")
    return nil
  }

  gHandler = handler
  return &Ebpflow{ ebpf: ebpfp }
}

func (e Ebpflow) Term () {
  C.term_ebpf_flow(e.ebpf);
}

func (e Ebpflow) Poll(timeout int) {
  C.ebpf_poll_event(e.ebpf, (_Ctype_uint)(timeout));
}

func c2TaskInfo (p _Ctype_struct_taskInfo) TaskInfo {
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

  goevent := BPFevent {
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
    Cgroup_id: C.GoString(&filled_event.cgroup_id[0]),
  }
  if (filled_event.ip_version == 4) {
    ipv4 := (*C.struct_ipv4_kernel_data)(unsafe.Pointer(&filled_event.event[0]))
    goevent.Saddr = make(net.IP, 4)
    binary.LittleEndian.PutUint32(goevent.Saddr, (uint32)(ipv4.saddr))
    goevent.Daddr = make(net.IP, 4)
    binary.LittleEndian.PutUint32(goevent.Daddr, (uint32)(ipv4.daddr))
  } else {
    ipv6 := (*C.struct_ipv6_kernel_data)(unsafe.Pointer(&filled_event.event[0]))
    saddr := ([16]byte)(ipv6.saddr)
    goevent.Saddr = net.ParseIP(string(saddr[:]))
    daddr := ([16]byte)(ipv6.daddr)
    goevent.Daddr = net.ParseIP(string(daddr[:]))
  }
  if (filled_event.docker != nil) {
    goevent.Docker = &DockerInfo {
      Dname: C.GoString(&filled_event.docker.dname[0]),
    }
    if (filled_event.kube != nil) {
      goevent.Kube = &KubeInfo {
        Pod: C.GoString(&filled_event.kube.pod[0]),
        Ns: C.GoString(&filled_event.kube.ns[0]),
      }
    }
  }
  gHandler(goevent)

  C.ebpf_free_event(filled_event)
}





