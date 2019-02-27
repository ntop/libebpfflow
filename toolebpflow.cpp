#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <stdio.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <regex>

#include <fstream>
#include <iostream>
#include <string>
#include <sstream>
#include <climits>
#include <bcc/BPF.h>

#include "ebpf_flow.h"


using namespace std;


int gDOCKER_ENABLE=1;
int gRUNNING = 1;

void help();
char* intoaV4(unsigned int addr, char* buf, u_short bufLen);
char* intoaV6(unsigned __int128 addr, char* buf, u_short bufLen);
void etype2str (int t_proto, char* t_buffer, int t_size);
static void HandleEvent(void* t_bpfctx, void* t_data, int t_datasize);
string LoadEBPF(string t_filepath);
int AttachWrapper(ebpf::BPF* bpf, string t_kernel_fun, string t_ebpf_fun, bpf_probe_attach_type attach_type);
static int attachEBPFTracepoint(ebpf::BPF *bpf, const char *tracepoint, const char *probe_func);
int parse_uargs(int argc, char const *argv[]);
void print_usage();
static void HandleTermination(int t_s=0);


/* **************************** */
// ===== ===== MAIN ===== ===== //
/* **************************** */
static const struct option long_opts[] = {
	{ "retr", 0, 0, 'r' },
	{ "tcpclose", 0, 0, 'c' },
	{ "udp", 0, 0, 'u' }, 
	{ "tcp", 0, 0, 't' },
	{ "in", 0, 0, 'i' },
	{ "out", 0, 0, 'o' },
	{ "docker", 0, 0, 'd' },
  { "help", 0, 0, 'h' }
};

int main(int argc, char **argv) { 
  ebpfRetCode rc;
  void *ebpf;

  signal(SIGINT, HandleTermination);

  // Argument Parsing ----- //
  int ch;
  int userarg_tcp=0, userarg_udp=0;
  int userarg_einput=0, userarg_eoutput=0;
  int userarg_retr=0, userarg_tcpclose=0;
  gDOCKER_ENABLE=0;
  while ((ch = getopt_long(argc, argv,
				                  "rcutiodh",
                          long_opts, NULL)) != EOF) {
      switch (ch) {
        case 'r':
          userarg_retr=1;
          break;
        case 'c': 
          userarg_tcpclose=1;
          break;
        case 'u':
          userarg_udp=1;
          break;
        case 't':
          userarg_tcp=1;
          break;
        case 'i':
          userarg_einput=1;
          break;
        case 'o':
          userarg_eoutput=1; 
          break;
        case 'd': 
          gDOCKER_ENABLE=1;        
          break;
        default:
          help();
          return 0;
    }
  }
  if (argc==1) {  
      userarg_tcp=1; userarg_udp=1;
      userarg_einput=1; userarg_eoutput=1;
      userarg_retr=1; userarg_tcpclose=1; 
  }   

  // Checking root ----- //
  if (getuid() != 0) {
    printf("Please run as root user \n");  
    return 0;
  }

  printf("Welcome to toolebpflow v.%s\n(C) 2018-19 ntop.org\n", 
   ebpf_flow_version());

  // Activating libebpflow ----- //
  printf("Initializing eBPF [%s]...\n",
#ifdef NEW_EBF
   "New API"
#else
   "Legacy API"
#endif
   );
  ebpf = init_ebpf_flow(NULL, HandleEvent, &rc);

  if(!ebpf) {
    printf("Unable to initialize libebpfflow: %s\n", ebpf_print_error(rc));
    return(rc);
  }
  printf("eBPF initializated successfully\n");

  // Polling event ----- //
  while(gRUNNING) {
    ebpf_poll_event(ebpf, 10);
  }

  // Cleaning and terminating ----- //
  term_ebpf_flow(ebpf);
  printf("eBPF terminated\n");
}

void help() {
  printf(
    "Usage: ebpflow [ OPTIONS ] \n"
    "   -h, --help      display this message \n"
    "   -t, --tcp       trace TCP only events \n"
    "   -u, --udp       trace UDP only events \n"
    "   -i, --in        trace only incoming events (i.e. TCP accept and UDP receive) \n"
    "   -i, --in        trace only outgoing events (i.e. TCP connect and UDP send) \n"
    "   -r, --retr      trace only retransmissions events \n"
    "   -c, --tcpclose  trace only tcp close events \n"
    "   -d, --docker    gather additional information concerning containers \n"
    "(default: every event is shown) \n"
    "Note: please run as root \n"
  );
}


/* ******************************************** */
// ===== ===== IP ADDRESS TO STRING ===== ===== //
/* ******************************************** */
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    // Taking last byte
    u_int byte = addr & 0xff;

    // Printing first cipher
    *--cp = byte % 10 + '0';
    byte /= 10;
    // Checking if there are more ciphers
    if(byte > 0) {
      // Writing second cipher
      *--cp = byte % 10 + '0';
      byte /= 10;
      // Writing third cipher
      if(byte > 0)
        *--cp = byte + '0';
    }
    // Adding '.' character between decimals
    *--cp = '.';
    // Shifting address of one byte (next step we'll take last byte)
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

char* intoaV6(unsigned __int128 addr, char* buf, u_short bufLen) {
  char *ret = (char*)inet_ntop(AF_INET6, &addr, buf, bufLen);

  if(ret == NULL) {
    buf[0] = '\0';
  }

  return(buf);
}


/* ***************************************** */
// ===== ===== CALLBACK HANDLERS ===== ===== //
/* ***************************************** */
void etype2str (__u8 net_proto, __u8 sent_packet, char* t_buffer, int t_size) {
  if (net_proto == IPPROTO_TCP) {
    if (sent_packet) 
      strncpy(t_buffer, "TCP/conn",  t_size);
    else strncpy(t_buffer, "TCP/acpt",  t_size);
  }
  else if (net_proto == IPPROTO_UDP) {
    if (sent_packet) 
      strncpy(t_buffer, "UDP/snd",  t_size);
    else strncpy(t_buffer, "UDP/rcv",  t_size);
  } 
  else strncpy(t_buffer, "?",  t_size);
}

static void HandleEvent(void* t_bpfctx, void* t_data, int t_datasize) {
  char event_type_str[17];
  eBPFevent *e = (eBPFevent*)t_data;

  // Preprocessing event ----- //
  eBPFevent event;
  // Copy needed as ebpf_preprocess_event will modify the memory
  memcpy(&event, e, sizeof(eBPFevent)); 
  ebpf_preprocess_event(&event, 1);

  // Event info ----- //
  printf("[ktime: %lu]", (long unsigned int)(event.ktime / 100000));

  // Task ----- //
  printf("[pid: %lu][uid: %lu][gid: %lu][%s] (task)\n",
    (long unsigned int)event.proc.gid,
    (long unsigned int)event.proc.uid,
    (long unsigned int)event.proc.pid,
    event.proc.task
  );

  // Parent ----- //
  printf("\t [pid: %lu][uid: %lu][gid: %lu][%s] (parent)\n",
    (long unsigned int)event.father.gid,
    (long unsigned int)event.father.uid,
    (long unsigned int)event.father.pid,
    event.father.task
  );

  // Network basic ----- //
  printf("\t [IPv%d]", event.ip_version);
  if (event.ip_version == 4) {
    // IPv4 Event type
    struct ipv4_kernel_data *ipv4_event = &event.event.v4; 
    etype2str(ipv4_event->net.proto, event.sent_packet, 
      event_type_str, sizeof(event_type_str));
    // IPv4 Network info
    char buf1[32], buf2[32];
    printf("\t [%s][addr: %s:%d <-> %s:%d] (net)\n",
      event_type_str,
      intoaV4(htonl(ipv4_event->saddr), buf1, sizeof(buf1)), ipv4_event->net.sport,
      intoaV4(htonl(ipv4_event->daddr), buf2, sizeof(buf2)), ipv4_event->net.dport);
    // IPv4 Latency if available
    if(ipv6_event->net.proto == IPPROTO_TCP)
      printf("[latency: %.2f msec]", ((float)event->net.latency_usec)/(float)1000);
  }
  else {
    // IPv6 Event type
    struct ipv6_kernel_data *ipv6_event = &event.event.v6; 
    etype2str(ipv6_event->net.proto, event.sent_packet, 
      event_type_str, sizeof(event_type_str));
    // IPv6 Network info
    char buf1[128], buf2[128];
    printf("\t [%s][addr: %s:%d <-> %s:%d] (net)\n",
      event_type_str,
      intoaV6(htonl(ipv6_event->saddr), buf1, sizeof(buf1)), ipv6_event->net.sport,
      intoaV6(htonl(ipv6_event->daddr), buf2, sizeof(buf2)), ipv6_event->net.dport);
    // IPv6 Latency if available
    if(ipv6_event->net.proto == IPPROTO_TCP)
      printf("[latency: %.2f msec]", ((float)event->net.latency_usec)/(float)1000);
  }

  // Container ----- //
  if (event.docker != NULL) printf("\t [docker: %.12s/%s] (docker)\n", event.cgroup_id, event.docker->dname);
  if (event.kube !=  NULL) printf("\t [kube pod/ns: %s/%s] (kubernetes)\n", event.kube->pod, event.kube->ns);  

  ebpf_free_event(&event);
}

static void HandleTermination(int t_s) {
  printf("\r* Terminating * \n");
  gRUNNING = 0;
}

