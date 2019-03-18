package main

import (
    e "./go"
    "os"
    "syscall"
    "os/signal"
    "fmt"
)

var gRUNNING bool = true

func main () {
  ebpf := e.NewEbppflow(event_handler)

  // Handle interruption
  c := make(chan os.Signal)
  signal.Notify(c, os.Interrupt, syscall.SIGTERM)
  go func() {
    <-c
    gRUNNING = false
  }()

  for gRUNNING == true {
    ebpf.Poll(10)
  }

  ebpf.Term()
 }

func event_handler (event e.BPFevent) {
  fmt.Printf("[%d][%d][%s][task:%s][path:%s][cgroup:%s]",
    event.Proc.Pid, event.EType, event.Ifname,
    event.Proc.Task, event.Proc.Full_Task_Path, event.Cgroup_id)
  fmt.Printf("[%s:%d <-> %s:%d]",
    event.Saddr.String(), event.Sport, event.Daddr.String(), event.Dport)
  if event.Docker != nil {
    fmt.Printf("[%s]", event.Docker.Dname)
  }
  fmt.Printf("\n")
}
