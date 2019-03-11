package main

import (
    "fmt"
    "os"
    "os/signal"
    "syscall"
    "unsafe"
)

/* 
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lebpfflow -lcurl -lbcc -ljson-c -lstdc++
#include "ebpf_flow.h"

#include <stdlib.h>

void go_handleEvent(void *t_bpfctx, void *t_data, int t_datalen);

static void* init (__u16 flags) {
  ebpfRetCode rc;
  return init_ebpf_flow(NULL, go_handleEvent, &rc, flags);
}

static eBPFevent* preprocess (eBPFevent *e) {  
  eBPFevent *event = malloc(sizeof(eBPFevent));
  memcpy(event, e, sizeof(eBPFevent));
  ebpf_preprocess_event(event, 0);
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

type taskInfo struct {
  Pid uint32
  Uid uint32
  Gid uint32
  Task [COMMAND_LEN]byte // task name
  Full_Task_Path *C.char
}

type ipv4_kernel_data struct {
  Saddr uint64
  Daddr uint64
}

type ipv6_kernel_data struct {
  Saddr [128]byte
  Daddr [128]byte
}

type dockerInfo struct {
  Dname [100]byte // Docker container name
}

type kubeInfo struct {
  Pod [60]byte;
  Ns [60]byte; // Kubernetes namespace
}

type eBPFevent struct {
  Ktime uint64 // Absolute kernel time
  Ifname [IFNAMSIZ]byte // net-dev name
  Event_time uint64 // Event time, filled during event preprocessing
  Ip_version uint8
  Sent_packet uint8
  EType etype // event type, supported events are listed in event_type enum

  V4 ipv4_kernel_data
  V6 ipv6_kernel_data

  Proto uint8
  Sport, dport uint16
  Latency_usec uint32
  Retransmissions uint16

  Proc taskInfo
  Father taskInfo

  Cgroup_id [CGROUP_ID_LEN]byte // Docker identifier
  // Both next fields are initializated to NULL and populated only during preprocessing
  Docker *dockerInfo
  Kube *kubeInfo
}

var gRUNNING = true

func main() {
  res, _ := C.ebpf_flow_version()
  fmt.Println("Invoking c library... ", C.GoString(res))

  // Initialization
  ebpf, _ := C.init(0)
  if ebpf == nil {
    fmt.Println("Error")
  }

  // Handle interruption
  c := make(chan os.Signal)
  signal.Notify(c, os.Interrupt, syscall.SIGTERM)
  go func() {
    <-c
    gRUNNING = false
  }()

  // Polling
  fmt.Printf("Ready to capture")
  for gRUNNING==true {
    C.ebpf_poll_event(ebpf, 10);
  }

  // Cleaning
  C.term_ebpf_flow(ebpf);
}

func charArray2goString () {

}

//export go_handleEvent
func go_handleEvent(t_bpfctx unsafe.Pointer, t_data unsafe.Pointer, t_datalen C.int) {
  event := (* C.eBPFevent)(t_data)
  filled_event := C.preprocess(event);

  fmt.Printf("[%d][task: %s][full_path: %s] \n",
      filled_event.ktime, C.GoString(&filled_event.proc.task[0]),
      C.GoString(filled_event.proc.full_task_path))

  C.ebpf_free_event(filled_event)
}
