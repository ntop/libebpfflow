#include <bcc/BPF.h>
#include "../../ebpf_flow.h"

int gRUNNING = 1;

static void event_handler(void* t_bpfctx, void* t_data, int t_datasize);
static void handl_signint(int t_s);
  
int main(int argc, char **argv) {
  // Return code
  ebpfRetCode rc;
  // This will store the object from which to poll
  void *ebpf;

  // Initialize the library to capture TCP events
  ebpf = init_ebpf_flow(NULL, event_handler, &rc, 
    LIBEBPF_TCP|LIBEBPF_INCOMING|LIBEBPF_OUTCOMING);

  if(!ebpf) {
    printf("Error: %s\n", ebpf_print_error(rc));
    return(rc);
  }

  printf("Initialized, start polling events");

  // Polling event with a timeout of 10ms
  while(gRUNNING) {
    ebpf_poll_event(ebpf, 10);
  }

  // Cleaning environment
  term_ebpf_flow(ebpf);

  return 0;
}


static void event_handler(void* t_bpfctx, void* t_data, int t_datasize) { 
  eBPFevent *e = (eBPFevent*)t_data;
  eBPFevent event;

  // Copy needed as ebpf_preprocess_event will modify the memory
  memcpy(&event, e, sizeof(eBPFevent));
  ebpf_preprocess_event(&event, 1, NULL);
 
  printf("[pid: %lu][%s]", 
    (long unsigned int)event.proc.pid, event.proc.task);
  
  // Cleaning environment
  ebpf_free_event(&event);
}


static void handl_signint(int t_s) {
  printf("Terminating");
  gRUNNING = 0;
}
