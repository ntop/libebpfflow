package main

import (
    ebpf_flow "./go"
    "os"
    "syscall"
    "os/signal"
    "fmt"
    "strings"
)

var gRUNNING bool = true

func main () {
  // Open ebpflow
  ebpf := ebpf_flow.NewEbpflow(event_handler, 0)
  fmt.Println("Initialzed")

  // Handle interruption
  c := make(chan os.Signal)
  signal.Notify(c, os.Interrupt, syscall.SIGTERM)
  go func() {
    <-c
    gRUNNING = false
  }()

  // Poll events
  for gRUNNING == true {
    ebpf.PollEvent(10)
  }

  // Clean resources
  ebpf.Close()
 }

func event_handler (event ebpf_flow.EBPFevent) {
  fmt.Printf("[pid:%d][etype:%d][%s][task:%s][path:%s]",
    event.Proc.Pid, event.EType, event.Ifname,
    event.Proc.Task, event.Proc.Full_Task_Path)
  fmt.Printf("[%s:%d <-> %s:%d]",
    event.Saddr.String(), event.Sport, event.Daddr.String(), event.Dport)
  if strings.Compare(event.Runtime, "")!=0 {
    fmt.Printf("[container_runtime: %s][container_id: %s]", event.Runtime, event.Cgroup_id[:16])
  }
  fmt.Printf("\n")
}
