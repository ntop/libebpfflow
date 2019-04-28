#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <sched.h>  
#include <linux/types.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include  <sys/socket.h>
#include <unistd.h>


#ifndef NETLINK_GENERIC
#define NETLINK_GENERIC 16
#endif

#ifndef SIOCETHTOOL
#define SIOCETHTOOL     0x8946
#endif

#define ETHTOOL_GSTATS  0x0000001d /* get NIC-specific statistics */

struct ethtool_stats {
    __u32   cmd;
    __u32   n_stats;
    __u64   data[10];
};

/* ************************************************** */

/*
 * Returns the peer of a veth network interface
 */
int getp (const char *ifname) {
    struct ifreq ifr;
    struct ethtool_stats *stats;
    int err, fd, res;

    // Opening socket fd 
    // (more details at http://man7.org/linux/man-pages/man7/netdevice.7.html)
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    
    // Setting target interface
    strcpy(ifr.ifr_name, ifname);
    // Setting request args 
    // (more details at https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ethtool.h#L662)
    stats = (struct ethtool_stats *) calloc(1, sizeof(struct ethtool_stats) + (sizeof(char) * 100));
    stats->cmd = ETHTOOL_GSTATS;
    ifr.ifr_data = (char*) stats;

    // Sending request to driver
    err = ioctl(fd, SIOCETHTOOL, &ifr);
    if (err < 0) {
        perror("> Cannot get stats information");
        res = -1;
        goto clean;
    }
    res = (int) (stats->data[0]);

clean:
    if (fd != -1)
        close(fd);
    if (stats != NULL)
        free(stats);
    return res;
}

/* ************************************************** */

/*
 * Returns the namespace filescritor in which the process with @pid is in
 */
int getnsfd (int pid, FILE **f) {
    char buff[120];
    int fp;

    // Getting user ns file desc
    snprintf(buff, sizeof(buff), "/proc/%d/ns/net", pid);
    *f = fopen(buff, "r");
    if(*f == NULL) {
        printf("%s\n", strerror(errno));
        fp = -1;
    }
    else { 
        fp = fileno(*f);
    }

    return fp;
}

/* ************************************************** */

/*
 * Given a container's pid, store in buff the veth interface's name 
 * assigned to the container. The buffer must allow for the storage of at least IF_NAMESIZE bytes
 */
int pid2ifname (int pid, char *t_buff) {
    FILE *usrf, *containerf;
    int usrns_fd, containerns_fd;
    int if_idx, res = 0;

    // Getting ns file desc 
    usrns_fd = getnsfd(1, &usrf);
    containerns_fd = getnsfd(pid, &containerf);

    // Jumping to ns
    setns(containerns_fd, CLONE_NEWNET);

    // Getting veth peer
    if_idx = getp("eth0");
    if(if_idx == -1) {
        res = -1;
        goto clean;
    }

    // Jumping back
    setns(usrns_fd, CLONE_NEWNET);

    // Converting
    if_indextoname(if_idx, t_buff);

clean:
    if (usrf != NULL)
        fclose(usrf);
    if (containerf != NULL)
        fclose(containerf);

    return res;
}

/* ************************************************** */

void help() {
    printf(
        "pid2veth: print the name of the virtual Ethernet associated with a container \n" 
        "given the pid of a task in it \n"
        "Usage: ./pid2veth <container_pid> \n"
    );
}

int main(int argc, char **argv) {
    char buff[IF_NAMESIZE];
    int pid; 
   
    if(argc < 2) {
        printf("> Please provide the pid of a task inside a container \n\n");
        help();
        return(-1);
    }
    
    if(getuid() != 0) {
        printf("> Please run as root \n\n");
        help();
        return 0;
    }

    pid = atoi(argv[1]);
    if(pid2ifname(pid, buff) == 0) {
        printf("%s\n", buff);
    }    

    return 0;
}
