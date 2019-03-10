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


// Every time the cache is cleaned, every entry
// with less than MINTOCLEAN accesses will be removed
#define MINTOCLEAN 50
// Cache cleaning interval in seconds
#define CLEAN_INTERVAL 30


struct cache_entry {
  int accessed;
  struct docker_api *value;
};

struct docker_api {
  char docker_name[100];
  int kube; // 1 if kubernetes info are available
  char kube_pod[60];
  char kube_namespace[60];
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
void docker_api_init ();

/*
 * Free the memory used by the library
 */
void docker_api_clean ();


/* ********************************************** */
// ===== ===== QUERY TO DOCKER DAEMON ===== ===== //
/* ********************************************** */

 
static size_t
WriteMemoryCallback (void *contents, size_t size, size_t nmemb, void *userp);

/* parse_response - fill a docker_api data structure with the information returned by a query to
 *   the docker daemon
 * return 0 if no error occurred -1 otherwise 
 */
int parse_response (char* buff, int buffsize, cache_entry **res);

/* 
 * update_query_cache - query to docker api from docker socket (/var/run/docker.sock) and caches the result.
 * @t_cgroupid: full length cgroup id
 * @t_dqr: filled with the information gathered if no error occurred
 * returns 0 if no error occurres otherwise -1
 * note: the same operation can be done using 
 *       `$ curl --unix-socket /var/run/docker.sock http://localhost/containers/<container-id>/json`
 */
int update_query_cache (char* t_cgroupid, struct cache_entry **t_dqr);


/* *********************************** */
// ===== ===== CACHE CHECK ===== ===== //
/* *********************************** */
/*
 * docker_id_cached - check if containers info have been cached
 * 		and if some info are available stores them in *t_dqs
 * @t_cgroupid: docker container ID
 * @t_dqs: will point to the cache entry if no error occurs (returns != -1)
 * returns 0 if the cache contains information concerning the container
 *	  	-1 if there no entry corresponding to the ID provided. 1 if 
 *		there is an entry associated with the ID but there aren't 
 *		information available
 */
int docker_id_cached (char *t_cgroupid, struct cache_entry **t_dqs);

/*
 * Clean the cache from queries far back in time and with less
 * than MINTOCLEAN or dummy entries from failed queries
 */
void clean_cache ();

/* ******************************* */
// ===== ===== QUERIES ===== ===== //
/* ******************************* */
/*
 * docker_id_get - sets a pointer to the associated information
 * @t_cgroupid: docker container ID
 * @t_dqs: will point to the container informations if no error occurs (returns != -1)
 * returns >0 if some information has been found, 1 if 
 * 		kubernetes information has been gathered. Returns -1 if no
 *		info are available 
 */
int docker_id_get (char* t_cgroupid, docker_api **t_dqr);

#endif /* __DOCKER_API_HPP__ */
