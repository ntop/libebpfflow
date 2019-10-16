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

#define CONTAINER_ID_LEN 128 // max is in dcache.h > DNAME_INLINE_LEN

#define COMMAND_LEN 16 // defined in sched.h

/*
 * Events types are forged as follows:
 *  I_digit (=1): init events (e.g. connection creation)
 *          (=2): update events on existing connection
 *          (=3): connection closing
 *          (=5): operation failed
 *  II_digit (=0): tcp events
 *           (=1): udp events
 *  III_digit: discriminate the single event
 */
typedef enum {
  eTCP_ACPT = 100,
  eTCP_CONN = 101,
  eTCP_RETR = 200,
  eUDP_RECV = 210,
  eUDP_SEND = 211,
  eTCP_CLOSE = 300,
  eTCP_CONN_FAIL = 500,
} event_type;

struct taskInfo {
  u32 pid; /* Process Id */
  u32 tid; /* Thread Id  */
  u32 uid; /* User Id    */
  u32 gid; /* Group Id   */
  char task[COMMAND_LEN], *full_task_path;
};

// separate data structs for ipv4 and ipv6
struct ipv4_addr_t {
  u64 saddr;
  u64 daddr;
};

struct ipv6_addr_t {
  unsigned __int128 saddr;
  unsigned __int128 daddr;
};

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

typedef struct {
  ktime_t ktime;
  char ifname[IFNAMSIZ];
  struct timeval event_time;
  u_int8_t ip_version, sent_packet;
  u16 etype;

  union {
    struct ipv4_addr_t v4;
    struct ipv6_addr_t v6;
  } addr;

  u8  proto;
  u16 sport, dport;
  u32 latency_usec;
  u16 retransmissions;

  struct taskInfo proc, father;
  char container_id[CONTAINER_ID_LEN];

  struct {
    char *name;
  } docker;
  
  struct {
    char *name;
    char *pod;
    char *ns;
  } kube;
} eBPFevent;

