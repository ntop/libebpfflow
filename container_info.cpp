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

#include "container_info.h"

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unordered_map>
#include <vector>
#include <set>
#include <regex>

#include <curl/curl.h>
#include <json-c/json.h>

#define DOCKERD_SOCK_PATH "/var/run/docker.sock"
#define MICROK8S_CTR_PATH "/snap/bin/microk8s.ctr"

// Cache where to store the queries results
static std::unordered_map<std::string, struct container_info> gQueryCache;

// Namespace cache
static std::set<std::string> namespaces;

static char ctr_path[64];

/* #define DEBUG */

/* ************************************************* */
// ===== ===== INITIALIZER AND DESTROYER ===== ===== //
/* ************************************************* */
void container_api_init() {
  struct stat s;

  gQueryCache.clear();

  if(stat(MICROK8S_CTR_PATH, &s) == 0)
    strcpy(ctr_path, MICROK8S_CTR_PATH);
  else
    strcpy(ctr_path, "ctr");

  update_namespaces();
}

void container_api_clean() {
  gQueryCache.clear();
  namespaces.clear();
}

/* ********************************************** */
// ===== ===== QUERY TO DOCKER DAEMON ===== ===== //
/* ********************************************** */
static size_t WriteMemoryCallback (void *contents, size_t size, size_t nmemb, void *userp) {
  size_t realsize = size * nmemb;
  struct ResponseBuffer *mem = (struct ResponseBuffer *) userp;

  char *ptr = (char*) realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
    /* out of memory! */
#ifdef DEBUG
    printf("not enough memory (realloc returned NULL)\n");
#endif
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

/* **************************************************** */

/* parse_response - fill a container_info data structure with the information returned by a query to
 * the docker daemon
 * return 0 if no error occurred -1 otherwise
 */
int parse_response(char* buff, int buffsize, struct container_info *entry) {
  int res_found = 0; // 1 if some info has been found
  struct json_object *jobj=NULL, *jlabel=NULL;
  struct json_object *jdockername, *jconfig, *jpodname, *jkubens;
  struct json_tokener *jtok;

#ifdef DEBUG
  printf("[%s:%u] %s(%s)\n", __FILE__, __LINE__, __FUNCTION__, buff);
#endif

  memset(entry, 0, sizeof(struct container_info));

  // Parsing req to json
  jtok = json_tokener_new();
  jobj = json_tokener_parse_ex(jtok, buff, buffsize);
  // We're not using it anymore, let's cleanup
  json_tokener_free(jtok);

  if(jobj == NULL)
    goto fail; 

  // Docker name
  if(json_object_object_get_ex(jobj, "Name", &jdockername)) {
    res_found = 1;
    entry->docker_name = std::string(json_object_get_string(jdockername)+1);
  }

  // Container labels
  if(json_object_object_get_ex(jobj, "Config", &jconfig)) /* json from docker api */
    json_object_object_get_ex(jconfig, "Labels", &jlabel);
  else /* json from containerd api */
    json_object_object_get_ex(jobj, "Labels", &jlabel);

  // Kubernetes info (when available)
  if(jlabel != NULL) {
    // Etracting kube info
    if(json_object_object_get_ex(jlabel, "io.kubernetes.pod.name", &jpodname)) {
      res_found = 1;
      entry->kube_pod = std::string(json_object_get_string(jpodname));
    }

    // Etracting kube info
    if(json_object_object_get_ex(jlabel, "io.kubernetes.pod.namespace", &jkubens)) {
      res_found = 1;
      entry->kube_namespace  = std::string(json_object_get_string(jkubens));
    }
  }

  if(!res_found)
    goto fail;

  json_object_put(jobj);
  return 0;

 fail:
  if(jobj)
    json_object_put(jobj);

  memset(entry, 0, sizeof(struct container_info));
  return(-1);
}

/* **************************************************** */

int dockerd_update_query_cache(char* t_cgroupid, struct container_info **t_dqr) {
  CURL *curl_handle;
  CURLcode res;
  char url[101];
  struct ResponseBuffer chunk;
  std::string cgroupid(t_cgroupid);
  struct stat s;
  struct container_info ci;

#ifdef DEBUG
  printf("[%s:%u] %s()\n", __FILE__, __LINE__, __FUNCTION__);
#endif

  (*t_dqr) = NULL;
  
  if(stat(DOCKERD_SOCK_PATH, &s) == -1)
    return(-1); /* Docker not found */

  // Crafting query
  snprintf(url, sizeof(url), "http://localhost/containers/%s/json", t_cgroupid);

  // Performing query ----- //
  // Initializing memory buffer
  chunk.memory = (char*) malloc(1);
  chunk.size = 0;
  // Preparing libcurl
  curl_handle = curl_easy_init();
  // URL
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  // Callback && Callback arguments
  curl_easy_setopt(curl_handle, CURLOPT_UNIX_SOCKET_PATH, DOCKERD_SOCK_PATH);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

  res = curl_easy_perform(curl_handle);

  // Checking for errors
  if(res != CURLE_OK) /* Create dummy entry */ {
#ifdef DEBUG
    printf("curl_easy_perform(%s) failed: %s\n", url, curl_easy_strerror(res));
#endif
    if(parse_response(NULL, 0, &ci) == -1)
      return(-1);
  } else {
    if(parse_response(chunk.memory, chunk.size, &ci) == -1)
      return(-1);
  }

  // Adding entry to table and pointing argument to entry
  gQueryCache[t_cgroupid] = ci;

  // Cleaning up
  curl_easy_cleanup(curl_handle);
  free(chunk.memory);
  curl_global_cleanup();

  *t_dqr = &(gQueryCache[t_cgroupid]);
  
  return(0);
}

/* **************************************************** */

int containerd_update_query_cache (char* t_cgroupid, struct container_info **t_dqr) {
  FILE *fp;
  char *ns;
  char res[700];
  char comm[132]; // 48 for "ctr --namespace=<ns> c i <c_id> 2>/dev/null" + 64 for containerid + 20 for namespace
  char buff[120];
  std::string cgroupid(t_cgroupid);
  std::set<std::string>::iterator s;
  struct container_info ci;

#ifdef DEBUG
  printf("[%s:%u] %s()\n", __FILE__, __LINE__, __FUNCTION__);
#endif

  (*t_dqr) = NULL;
  
  if(!std::regex_match(cgroupid, std::regex("^([0-9a-zA-Z\\.\\_\\-])*$")))
    return -1;

  for(s = namespaces.begin(); s != namespaces.end(); ++s) {
    ns = (char*) (*s).c_str();

    /* ***** ***** SANITIZE THE INPUT ***** ***** */
    // The container id and namespace MUST be sanitized
    // otherwise there's a risk of command injection
    // cgroupid has been already sanitized
    /* ***** ***** ****************** ***** ***** */
    if(!std::regex_match(*s, std::regex("^([0-9a-zA-Z\\.\\_\\-])*$")))
      return -1;

    snprintf(comm, sizeof(comm), "%s --namespace=%s  c info %s 2>/dev/null",
	     ctr_path, ns, t_cgroupid);

    // piping to the command
    fp = popen(comm, "r");
    if(fp == NULL) {
#ifdef DEBUG
      printf("containerd interaction failed \n");
#endif
      return -1;
    }

    // concatenate output line by line. Kube info are provided in the fs 8 lines
    strcpy(buff, "");
    strcpy(res, "");
    for(int i=0; i<8; i++) {
      if(fgets(buff, sizeof(buff)-1, fp) == NULL) break;
      strncat(res, buff, sizeof(res)-strlen(res)-1);
    }
    
    // only kubernetes info are extracted, we need to repair the json
    strncat(res, "}}", sizeof(res)-strlen(res)-1);

    pclose(fp);

    // handling json
    if(parse_response(res, sizeof(res), &ci) == -1)
      return(-1);
  }

  gQueryCache[t_cgroupid] = ci;
  *t_dqr = &(gQueryCache[t_cgroupid]);
  
  return(1);
}

/* **************************************************** */

int update_namespaces() {
  FILE *fp;
  int i = 0;
  char ns[20];
  char buf[64];

#ifdef DEBUG
  printf("[%s:%u] %s()\n", __FILE__, __LINE__, __FUNCTION__);
#endif
  
  namespaces.clear();

  snprintf(buf, sizeof(buf), "%s namespace ls 2>/dev/null", ctr_path);

#ifdef DEBUG
  printf("[%s:%u] %s\n", __FILE__, __LINE__, buf);
#endif
  if((fp = popen(buf, "r")) == NULL)
    return(-1);

  while(fgets(ns, sizeof(ns)-1, fp) != NULL) {
    char *space;

    if(i == 0) /* Fs line is the title */ {
      i++;
      continue;
    }

    if((space = strchr(ns, ' ')) != NULL)
      space[0] = '\0';

#ifdef DEBUG
    printf("[%s:%u] Found namespeace %s\n", __FILE__, __LINE__, space);
#endif

    namespaces.insert(ns);
  }

  pclose(fp);
  return(0);
}

/* **************************************************** */

/* *********************************** */
// ===== ===== CACHE CHECK ===== ===== //
/* *********************************** */
/*
 * container_id_find_in_cache - check if containers info have been cached
 * returns -1 if the query has not been cached 0 if some info are available
 *  1 for dummy keys
 */
int container_id_find_in_cache(char* t_cgroupid, struct container_info **t_dqs) {
  std::string cgroupid(t_cgroupid);
  std::unordered_map<std::string, struct container_info>::iterator res = gQueryCache.find(cgroupid);

  if(res != gQueryCache.end()) {
    *t_dqs = &(res->second);
    
    return 0;
  } else
    return(-1);
}

/* **************************************************** */

/* ******************************* */
// ===== ===== QUERIES ===== ===== //
/* ******************************* */

int container_id_get(char* t_cgroupid, struct container_info **t_dqr) {
  int res;
  static time_t last = time(NULL);
  time_t now = time(NULL);

#ifdef DEBUG
  printf("[%s:%u] %s(%s)\n", __FILE__, __LINE__, __FUNCTION__, t_cgroupid);
#endif

  if((t_cgroupid[0] == '\0') || (strcmp(t_cgroupid, "/") == 0))
    return(-1);
  
  if(difftime(now, last) > REFRESH_TIME /* Seconds */ ) {
    int rc;

    namespaces.clear();
    rc = update_namespaces();
    last = now;

    if(rc == -1) return(rc);
  }

  res = container_id_find_in_cache(t_cgroupid, t_dqr);
  if(res != -1) /* Item is cached */
    return(res);  

  // Dockerd
  res = dockerd_update_query_cache(t_cgroupid, t_dqr);

  // Containerd interaction
  if(res != 0)
    res = containerd_update_query_cache(t_cgroupid, t_dqr);

  return(res);
}
