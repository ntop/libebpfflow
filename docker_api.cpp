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

#include "docker_api.h"

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unordered_map>
#include <vector>

#include <curl/curl.h>
#include <json-c/json.h>


// Docker daemon query url
const char* query_from_id = "http://localhost/containers/%s/json";
// Cache where to store the queries results
std::unordered_map<std::string, struct cache_entry*> *gQueryCache = nullptr;


/* ************************************************* */
// ===== ===== INITIALIZER AND DESTROYER ===== ===== //
/* ************************************************* */
void docker_api_init () {
  gQueryCache = new std::unordered_map<std::string, struct cache_entry*>; 
}

void clean_cache_entry (struct cache_entry *e) {
  if (e->value != nullptr) {
    free(e->value);
  }
  free(e);
}

void docker_api_clean () {
  if (gQueryCache==nullptr) return;

  std::unordered_map<std::string, struct cache_entry*>::iterator it; 
  for (it=gQueryCache->begin(); it!=gQueryCache->end(); it++) { 
    clean_cache_entry(it->second);
  }
  delete gQueryCache;
  gQueryCache = nullptr;
}


/* ********************************************** */
// ===== ===== QUERY TO DOCKER DAEMON ===== ===== //
/* ********************************************** */
static size_t
WriteMemoryCallback (void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct ResponseBuffer *mem = (struct ResponseBuffer *) userp;
 
  char *ptr = (char*) realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
    /* out of memory! */ 
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

/* parse_response - fill a docker_api data structure with the information returned by a query to
 *   the docker daemon
 * return 0 if no error occurred -1 otherwise 
 */
int parse_response (char* buff, int buffsize, cache_entry **res) { 
  struct json_object *jobj = NULL;
  struct json_object *jdockername, *jconfig, *jlabel, *jpodname, *jkubens;
  struct json_tokener *jtok;
  struct cache_entry *entry;
  struct docker_api *dqr;

  // Creating cache entry
  entry = (struct cache_entry *) malloc(sizeof(struct cache_entry));
  entry->value = NULL;

  // Dummy entry
  if (buff == NULL) {
    goto fail;
  }

  // Trying to populate if not empty
  dqr = (struct docker_api *) malloc(sizeof(struct docker_api));
  entry->value = dqr;
  dqr->kube = 0;

  // Parsing req to json
  jtok = json_tokener_new();
  jobj = json_tokener_parse_ex(jtok, buff, buffsize);
  // We're not using it anymore, let's cleanup
  json_tokener_free(jtok);

  if (jobj == NULL) {
    goto fail;
  };

  // Docker name
  if (json_object_object_get_ex(jobj, "Name", &jdockername)) {
    strcpy(dqr->docker_name, json_object_get_string(jdockername)+1);
  }
  else goto fail;
  

  // Checking kube info 
  if (json_object_object_get_ex(jobj, "Config", &jconfig) && 
    json_object_object_get_ex(jconfig, "Labels", &jlabel)) {
      // Etracting kube info
      if (json_object_object_get_ex(jlabel, "io.kubernetes.pod.name", &jpodname)) {
        strcpy(dqr->kube_pod, json_object_get_string(jpodname));
        dqr->kube = 1;
      }
      // Etracting kube info
      if (json_object_object_get_ex(jlabel, "io.kubernetes.pod.namespace", &jkubens)) {
        strcpy(dqr->kube_namespace, json_object_get_string(jkubens));
        dqr->kube = 1;
      }
  }

  json_object_put(jobj);
  *res = entry;
  return 0;

fail:
  if (jobj) { 
    json_object_put(jobj);
  }
  if (dqr != NULL){
    free(dqr);
  }
  entry->value = NULL;
  *res = entry;
  return -1;
}

/* 
 * update_query_cache - query to docker api from docker socket (/var/run/docker.sock) and caches the result.
 * @t_cgroupid: full length cgroup id
 * @t_dqr: filled with the information gathered if no error occurred
 * returns 0 if no error occurred and associate info are found, otherwise -1
 * note: the same operation can be done using 
 *       `$ curl --unix-socket /var/run/docker.sock http://localhost/containers/<container-id>/json`
 */
int update_query_cache (char* t_cgroupid, struct cache_entry **t_dqr) {
  CURL *curl_handle;
  CURLcode res;
  char url[101];
  cache_entry *dqr;
  std::string cgroupid(t_cgroupid);
  // Crafting query
  snprintf(url, sizeof(url), query_from_id, t_cgroupid);
  
  // Performing query ----- //
  // Initializing memory buffer
  struct ResponseBuffer chunk;
  chunk.memory = (char*) malloc(1);   
  chunk.size = 0;
  // Preparing libcurl  
  curl_handle = curl_easy_init();
  // URL
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  // Callback && Callback arguments
  curl_easy_setopt(curl_handle, CURLOPT_UNIX_SOCKET_PATH, "/var/run/docker.sock");
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback); 
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
  
  res = curl_easy_perform(curl_handle);

  // Checking for errors
  if(res != CURLE_OK) /* Create dummy entry */ {
    printf("curl_easy_perform(%s) failed: %s\n", url, curl_easy_strerror(res));
    parse_response(NULL, 0, &dqr);
  }
  else {
    parse_response(chunk.memory, chunk.size, &dqr);
    // Setting accessed times to zero
    dqr->accessed = 0;
  }

  // Adding entry to table and pointing argument to entry
  gQueryCache->emplace(cgroupid, dqr);
  *t_dqr = dqr;

  // Cleaning up
  curl_easy_cleanup(curl_handle);
  free(chunk.memory);
  curl_global_cleanup();
  
  return (dqr->value == NULL ? -1:0);
}


/* *********************************** */
// ===== ===== CACHE CHECK ===== ===== //
/* *********************************** */
/*
 * docker_id_cached - check if containers info have been cached
 * returns -1 if the query has not been cached 0 if some info are available
 *  1 for dummy keys
 */
int docker_id_cached (std::string t_cgroupid, struct cache_entry **t_dqs) {
  std::unordered_map<std::string, struct cache_entry*>::iterator res;  
  res = gQueryCache->find(t_cgroupid);

  if (res != gQueryCache->end()) {
    if (res->second->value != nullptr) {
      res->second->accessed += 1;
      *t_dqs = res->second;
      return 0;
    }
    return 1; 
  }
  return -1;
}


void clean_cache () {
  std::vector<std::string> markedentries;
  std::vector<std::string>::iterator marked_it;
  std::unordered_map<std::string, struct cache_entry*>::iterator it;

  if (gQueryCache==nullptr) return;

  // Getting entries accessed less than MINTOCLEAN times 
  for (it=gQueryCache->begin(); it!=gQueryCache->end(); it++) {
    struct cache_entry *entry = it->second; 
    if (entry->accessed < MINTOCLEAN || entry->value==nullptr) {
      markedentries.push_back(it->first);
      clean_cache_entry(it->second);
    }
    else {
      it->second->accessed = 0;
    }
  }

  for (marked_it=markedentries.begin(); marked_it!=markedentries.end(); marked_it++) {
    gQueryCache->erase(*marked_it); 
  }
}


/* ******************************* */
// ===== ===== QUERIES ===== ===== //
/* ******************************* */
int docker_id_get (char* t_cgroupid, docker_api **t_dqr) {
  cache_entry* qr;
  std::string cgroupid(t_cgroupid);
  int res;
  
  static time_t last = time(nullptr);
  time_t now = time(nullptr);
  if (difftime(now, last) > CLEAN_INTERVAL /* Seconds */ ) {
    clean_cache();
    last = now;
  }

  if((t_cgroupid[0] == '\0') || (strcmp(t_cgroupid, "/") == 0)) {
    return -1; 
  }
  
  res = docker_id_cached(cgroupid, &qr);
  if (res == 1) {
    return -1;
  }
  else if (res == 0 || update_query_cache(t_cgroupid, &qr) == 0) {
    *t_dqr = qr->value;
    return (*t_dqr)->kube; 
  }
  return -1;
} 

