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

#ifndef __DOCKER_API_HPP__
#define __DOCKER_API_HPP__ 1

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unordered_map>

// Cache cleaning and namespace update interval in seconds
#define REFRESH_TIME 30

struct container_info {
  std::string docker_name, kube_pod, kube_namespace;
};

struct cache_entry {
  int num_uses;
  struct container_info content;
};

// Used to store libcurl partial results
struct ResponseBuffer {
  char *memory;
  size_t size;
};

/* ************************************************* */
// ===== ===== INITIALIZER AND DESTROYER ===== ===== //
/* ************************************************* */
/*
 * Initializes the docker interaction library, make sure to call
 * it before invoking any other library function
 */
void container_api_init ();

/*
 * Free the memory used by the library
 */
void container_api_clean ();

/*
 * Gather namespaces from ctr or docker-containerd-ctr
 */
int update_namespaces();

/* 
 * Removes from the cache all those entries that have been accessed less than MIN_VISITS times
 */
void clean_cache();

/*
 * Create the entry if it does not exist, otherwise updates the content
 */
void update_cache_entry(char* t_cgroupid, struct cache_entry *t_dqr);

/* ********************************************** */
// ===== ===== QUERY TO DOCKER DAEMON ===== ===== //
/* ********************************************** */
 
/* parse_response - fill a container_info data structure with the information returned by a query to
 *   the docker daemon
 * buff: if NULL a dummy entry will be created (not added to the cache)
 * return 0 if no error occurred -1 otherwise 
 */
int parse_response (char* buff, int buffsize, cache_entry **res);

/* 
 * update_query_cache - query to docker api from docker socket (/var/run/docker.sock) and caches the result.
 * @t_cgroupid: full length cgroup id
 * @t_dqr: filled with the information gathered if no error occurred
 * returns 0 if no error occurres and container info has been found, otherwise -1
 * note: the same operation can be done using 
 *       `$ curl --unix-socket /var/run/docker.sock http://localhost/containers/<container-id>/json`
 */
int dockerd_update_query_cache (char* t_cgroupid, struct cache_entry **t_dqr);

/* 
 * update_query_cache - exec ctr (i.e. containerd cli) to retrieve information
 *  concerning the container. If ctr is not available it will be tried: docker-containerd-ctr
 * @t_cgroupid: full length cgroup id
 * @t_ns: target namespace
 * @t_dqr: filled with the information gathered if no error occurred
 * returns 0 if no error occurres and container info has been found, otherwise -1
 * note: the same operation can be done using 
 *       `$ sudo ctr --namespace=<namespace> containers info <container-id>`
 */
int containerd_update_query_cache (char* t_cgroupid, struct cache_entry **t_dqr, char *ns);

/* *********************************** */
// ===== ===== CACHE CHECK ===== ===== //
/* *********************************** */
/*
 * container_id_cached - check if containers info have been cached
 *    and if some info are available stores them in *t_dqs
 * @t_cgroupid: docker container ID
 * @t_dqs: will point to the cache entry if no error occurs (returns != -1)
 * returns 0 if the cache contains information concerning the container
 *      -1 if there no entry corresponding to the ID provided. 1 if 
 *    there is an entry associated with the ID but there isn't 
 *    information available
 */
int container_id_cached (char *t_cgroupid, struct cache_entry **t_dqs);

/*
 * Clean the cache from queries far back in time and with less
 * than MINTOCLEAN or dummy entries from failed queries
 */
void clean_cache ();

/* ******************************* */
// ===== ===== QUERIES ===== ===== //
/* ******************************* */
/*
 * container_id_get - sets a pointer to the associated information
 * @t_cgroupid: docker container ID
 * @t_dqs: will point to the container informations if no error occurs (returns != -1)
 * returns 0 if some info has been found, -1 otherwise

 */
int container_id_get (char* t_cgroupid, container_info **t_dqr);

#endif /* __DOCKER_API_HPP__ */
