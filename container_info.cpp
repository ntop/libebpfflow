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
#include <regex>

#include <curl/curl.h>
#include <json-c/json.h>

#define DOCKERD_SOCK_PATH "/var/run/docker.sock"
#define MICROK8S_CTR_PATH "/snap/bin/microk8s.ctr"

// Docker daemon query url
const char* query_from_id = "http://localhost/containers/%s/json";
// Cache where to store the queries results
std::unordered_map<std::string, struct cache_entry*> *gQueryCache = NULL;
// Namespace cache
std::vector<std::string*> *namespaces = NULL;

static char ctr_path[64];

/* ************************************************* */
// ===== ===== INITIALIZER AND DESTROYER ===== ===== //
/* ************************************************* */
void container_api_init () {
  struct stat s;

  gQueryCache = new std::unordered_map<std::string, struct cache_entry*>;
  namespaces = new std::vector<std::string*>();
  update_namespaces();

  if(stat(MICROK8S_CTR_PATH, &s) == 0)
    strcpy(ctr_path, MICROK8S_CTR_PATH);
  else
    strcpy(ctr_path, "ctr");
}

/* **************************************************** */

void clean_cache_entry (struct cache_entry *e) {
  if(e->value != NULL)
    free(e->value);
  free(e);
}

/* **************************************************** */

void container_api_clean () {
  std::unordered_map<std::string, struct cache_entry*>::iterator it;

  if(gQueryCache == NULL) return;

  for(it=gQueryCache->begin(); it!=gQueryCache->end(); it++) {
    clean_cache_entry(it->second);
  }

  delete gQueryCache;
  gQueryCache = NULL;
}

/* **************************************************** */

void update_cache_entry(std::string t_cgroupid, struct cache_entry *t_dqr) {
  std::pair<std::unordered_map<std::string, struct cache_entry*>::iterator, bool> res;
  res = gQueryCache->insert(std::make_pair(t_cgroupid, t_dqr));

  if(!res.second) /* Update */ {
    void *p = res.first->second;

    (*gQueryCache)[t_cgroupid] = t_dqr;
    if(p) free(p);
  }
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
 *   the docker daemon
 * return 0 if no error occurred -1 otherwise
 */
int parse_response(char* buff, int buffsize, cache_entry **res) {
  int res_found = 0; // 1 if some info has been found
  struct json_object *jobj=NULL, *jlabel=NULL;
  struct json_object *jdockername, *jconfig, *jpodname, *jkubens;
  struct json_tokener *jtok;
  struct cache_entry *entry;
  struct container_info *dqr;

  // Creating cache entry
  entry = (struct cache_entry *) malloc(sizeof(struct cache_entry));
  if(!entry)
    return(-1);
  
  entry->value = NULL;

  // Dummy entry
  if(buff == NULL) {
    goto fail;
  }

  // Initializing new cache entry value
  dqr = (struct container_info *)calloc(1, sizeof(struct container_info));

  // Trying to populate if not empty
  entry->value = dqr;

  // Parsing req to json
  jtok = json_tokener_new();
  jobj = json_tokener_parse_ex(jtok, buff, buffsize);
  // We're not using it anymore, let's cleanup
  json_tokener_free(jtok);

  if(jobj == NULL) {
    goto fail;
  };

  // Docker name
  if(json_object_object_get_ex(jobj, "Name", &jdockername)) {
    res_found = 1;
    strcpy(dqr->docker_name, json_object_get_string(jdockername)+1);
  }

  // Container labels
  if(json_object_object_get_ex(jobj, "Config", &jconfig)) /* json from docker api */ {
    json_object_object_get_ex(jconfig, "Labels", &jlabel);
  }
  else /* json from containerd api */ {
    json_object_object_get_ex(jobj, "Labels", &jlabel);
  }

  // Kubernetes info (when available)
  if(jlabel != NULL) {
    // Etracting kube info
    if(json_object_object_get_ex(jlabel, "io.kubernetes.pod.name", &jpodname)) {
      res_found = 1;
      strcpy(dqr->kube_pod, json_object_get_string(jpodname));
    }
    // Etracting kube info
    if(json_object_object_get_ex(jlabel, "io.kubernetes.pod.namespace", &jkubens)) {
      res_found = 1;
      strcpy(dqr->kube_namespace, json_object_get_string(jkubens));
    }
  }

  if(!res_found) {
    goto fail;
  }

  json_object_put(jobj);
  *res = entry;
  return 0;

 fail:
  if(jobj)
    json_object_put(jobj);
  
  if(dqr != NULL)
    free(dqr);
  
  entry->value = NULL;
  *res = entry;
  return -1;
}

/* **************************************************** */

int dockerd_update_query_cache (char* t_cgroupid, struct cache_entry **t_dqr) {
  CURL *curl_handle;
  CURLcode res;
  char url[101];
  struct ResponseBuffer chunk;
  cache_entry *dqr;
  std::string cgroupid(t_cgroupid);
  struct stat s;

  if(stat(DOCKERD_SOCK_PATH, &s) == -1)
    return(-1); /* Docker not found */
	   
  // Crafting query
  snprintf(url, sizeof(url), query_from_id, t_cgroupid);
    
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
    if(parse_response(NULL, 0, &dqr) == -1)
      return(-1);
  } else {
    parse_response(chunk.memory, chunk.size, &dqr);
    // Setting accessed times to zero
    dqr->accessed = 0;
  }

  if(dqr->value != NULL)
    strncpy(dqr->value->runtime, "docker", sizeof(dqr->value->runtime));  

  // Adding entry to table and pointing argument to entry
  update_cache_entry(cgroupid, dqr);
  *t_dqr = dqr;

  // Cleaning up
  curl_easy_cleanup(curl_handle);
  free(chunk.memory);
  curl_global_cleanup();

  return(dqr->value == NULL ? -1:0);
}

/* **************************************************** */

int containerd_update_query_cache (char* t_cgroupid, struct cache_entry **t_dqr) {
  FILE *fp;
  char *ns;
  cache_entry *dqr = NULL;
  char res[700];
  char comm[132]; // 48 for "ctr --namespace=<ns> c i <c_id> 2>/dev/null" + 64 for containerid + 20 for namespace
  char buff[120];
  std::string cgroupid(t_cgroupid);
  std::vector<std::string*>::iterator s;

  if(!std::regex_match(cgroupid, std::regex("^([0-9a-zA-Z\\.\\_\\-])*$")))
    return -1;  

  for(s = namespaces->begin(); s != namespaces->end(); ++s) {
    ns = (char*) (*s)->c_str();

    /* ***** ***** SANITIZE THE INPUT ***** ***** */
    // The container id and namespace MUST be sanitized
    // otherwise there's a risk of command injection
    // cgroupid has been already sanitized
    /* ***** ***** ****************** ***** ***** */
    if(!std::regex_match(**s, std::regex("^([0-9a-zA-Z\\.\\_\\-])*$")))
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
    for(int i=0; i<8; i++){
      if(fgets(buff, sizeof(buff)-1, fp) == NULL) break;
      strncat(res, buff, sizeof(res)-strlen(res)-1);
    }
    // only kubernetes info are extracted, we need to repair the json
    strncat(res, "}}", sizeof(res)-strlen(res)-1);

    pclose(fp);

    // handling json
    parse_response(res, sizeof(res), &dqr);
    if(dqr->value != NULL) {
      break;
    }
  }

  if(dqr == NULL) return(-1);
  
  // At the end of the iteration we should have the value stored in dqr
  // in both cases in which dqr is a dummy key or contains info

  if(dqr->value != NULL)
    strncpy(dqr->value->runtime, "containerd", sizeof(dqr->value->runtime));  

  // Adding entry to table and pointing argument to entry
  update_cache_entry(cgroupid, dqr);
  *t_dqr = dqr;

  return (dqr->value == NULL ? -1:0);
}

/* **************************************************** */

int update_namespaces () {
  FILE *fp;
  std::vector<std::string*>::iterator s;
  int i = 0;
  char ns[20];
  char buf[64];

  snprintf(buf, sizeof(buf), "%s namespace ls 2>/dev/null", ctr_path);
  
  fp = popen(buf, "r");
  if(fp == NULL) {
#ifdef DEBUG
    printf("Failing to list namespaces \n");
#endif
    return -1;
  }
  
  while(fgets(ns, sizeof(ns)-1, fp) != NULL) {
    if(i==0) /* Fs line is the title */ {
      i++;
      continue;
    }
    // Adding namespace
    std::string *string_ns = new std::string(ns);
    // Trimming string
    string_ns->pop_back();
    size_t last = string_ns->find_last_not_of(' ');
    string_ns->erase(last+1, string_ns->length());

    // Check if the namespace already exists
    for(s = namespaces->begin(); s != namespaces->end(); ++s) {
      if((*s)->compare(*string_ns) == 0) {
        break;
      }
    }
    // Add if not exist
    if(s == namespaces->end()) {
      namespaces->push_back(string_ns);
    }
  }

  pclose(fp);
  
  return -1;
}

/* **************************************************** */

/* *********************************** */
// ===== ===== CACHE CHECK ===== ===== //
/* *********************************** */
/*
 * container_id_cached - check if containers info have been cached
 * returns -1 if the query has not been cached 0 if some info are available
 *  1 for dummy keys
 */
int container_id_cached (char* t_cgroupid, struct cache_entry **t_dqs) {
  std::string cgroupid(t_cgroupid);
  std::unordered_map<std::string, struct cache_entry*>::iterator res;
  res = gQueryCache->find(cgroupid);

  if(res != gQueryCache->end()) {
    if(res->second->value != NULL) {
      res->second->accessed += 1;
      *t_dqs = res->second;
      return 0;
    }
    return 1;
  }
  return -1;
}

/* **************************************************** */

void clean_cache () {
  struct cache_entry *entry;
  std::vector<std::string> markedentries;
  std::vector<std::string>::iterator marked_it;
  std::unordered_map<std::string, struct cache_entry*>::iterator it;

  if(gQueryCache == NULL) return;

  // Getting entries accessed less than MINTOCLEAN times
  for(it=gQueryCache->begin(); it!=gQueryCache->end(); it++) {
    entry = it->second;
    if(entry->accessed < MINTOCLEAN || entry->value == NULL) {
      markedentries.push_back(it->first);
      clean_cache_entry(it->second);
    } else {
      it->second->accessed = 0;
    }
  }

  for(marked_it=markedentries.begin(); marked_it!=markedentries.end(); marked_it++) {
    gQueryCache->erase(*marked_it);
  }
}

/* **************************************************** */

/* ******************************* */
// ===== ===== QUERIES ===== ===== //
/* ******************************* */
int container_id_get(char* t_cgroupid, container_info **t_dqr, char* runtime) {
  cache_entry* qr;
  int res;
  static time_t last = time(NULL);
  time_t now = time(NULL);

  if(difftime(now, last) > REFRESH_TIME /* Seconds */ ) {
    int rc;
    
    clean_cache();
    rc = update_namespaces();
    last = now;
    
    if(rc == -1) return(rc);
  }

  if((t_cgroupid[0] == '\0') || (strcmp(t_cgroupid, "/") == 0)) {
    return -1;
  }

  res = container_id_cached(t_cgroupid, &qr);
  if(res != -1) /* Item is cached */ {
    *t_dqr = qr->value;
    return (res==0 ? 0 : -1);
  }

  // Updating cache ----- //
  res = 0;
  // Dockerd
  if((runtime == NULL) || (strcmp(runtime, "docker") == 0))
    res = dockerd_update_query_cache(t_cgroupid, &qr);  
  
  // Containerd interaction
  if((res != 0) && ((runtime == NULL) || (strcmp(runtime, "containerd") == 0)))
    res = containerd_update_query_cache(t_cgroupid, &qr);  

  *t_dqr = qr->value;
  return res;
}

