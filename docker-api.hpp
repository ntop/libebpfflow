#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <unordered_map>
#include <vector>

#include <curl/curl.h>
#include <json-c/json.h>


#define MINTOCLEAN 100

struct docker_api {
  int accessed;
  char docker_name[100];
  int kube; // 1 if kubernetes info are available
  char kube_pod[60];
  char kube_namespace[60];
};


// Docker daemon query url
const char* query_from_id = "http://localhost/containers/%s/json";
std::unordered_map<std::string, struct docker_api*> *gQueryCache = nullptr;

 
/* ************************************************* */
// ===== ===== INITIALIZER AND DESTROYER ===== ===== //
/* ************************************************* */
void docker_api_init () {
  gQueryCache = new std::unordered_map<std::string, struct docker_api*>; 
}

void docker_api_clean () {
  if (gQueryCache==nullptr) return;

  std::unordered_map<std::string, struct docker_api*>::iterator it; 
  for (it=gQueryCache->begin(); it!=gQueryCache->end(); it++) { 
    free(it->second);
  }
  delete gQueryCache;
  gQueryCache = nullptr;
}


/* ********************************************** */
// ===== ===== QUERY TO DOCKER DAEMON ===== ===== //
/* ********************************************** */
struct ResponseBuffer {
  char *memory;
  size_t size;
};
 
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
int parse_response (char* buff, int buffsize, docker_api **res) { 
  struct json_object *jobj, *jdockername, *jconfig, *jlabel, *jpodname, *jkubens;
  struct json_tokener *jtok;
  struct docker_api* dqr;

  // Creating the docker api heap data structure
  dqr = (struct docker_api *) malloc(sizeof(struct docker_api));
  dqr->kube = 0;

  // Parsing req to json
  jtok = json_tokener_new();
  jobj = json_tokener_parse_ex(jtok, buff, buffsize);
  // We're not using it anymore, let's cleanup
  json_tokener_free(jtok);

  if (jobj == NULL) {
    return -1;
  };

  // Docker name
  if (json_object_object_get_ex(jobj, "Name", &jdockername)) {
    strcpy(dqr->docker_name, json_object_get_string(jdockername)+1);
    printf("\n>%s\n", json_object_get_string(jdockername));
  }
  else {
    printf("\n%s\n", json_object_get_string(jobj));
    return -1;
  }

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
  *res = dqr;
  return 0;  
}

/* 
 * update_query_cache - query to docker api from docker socket (/var/run/docker.sock) and caches the result.
 * @t_cgroupid: full length cgroup id
 * @t_dqr: filled with the information gathered if no error occurred
 * returns 0 if no error occurres otherwise -1
 * note: the same operation can be done using 
 *       `$ curl --unix-socket /var/run/docker.sock http://localhost/containers/<container-id>/json`
 */
int update_query_cache (char* t_cgroupid, struct docker_api **t_dqr) {
  CURL *curl_handle;
  CURLcode res;
  char url[101];
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
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    return -1;
  }
  
  docker_api *dqr;
  if(parse_response(chunk.memory, chunk.size, &dqr) != 0) { 
    return -1;
  }
  std::string cgroupid(t_cgroupid);
  // Setting accessed times to zero
  dqr->accessed = 0;
  gQueryCache->emplace(cgroupid, dqr);
  *t_dqr = dqr;

  // Cleaning up
  curl_easy_cleanup(curl_handle);
  free(chunk.memory);
  curl_global_cleanup();
  return 0;
}


/* *********************************** */
// ===== ===== CACHE CHECK ===== ===== //
/* *********************************** */
/*
 * docker_id_cached - check if containers info have been cached
 * returns -1 if the query has not been cached 0 otherwise
 */
int docker_id_cached (std::string t_cgroupid, struct docker_api **t_dqs) {
  auto res = gQueryCache->find(t_cgroupid);

  if (res != gQueryCache->end()) {
    res->second->accessed += 1;
    *t_dqs = res->second;
    return 0;
  }
  else return -1;
}


void clean_cache () {
  std::vector<std::string> markedentries;
  std::vector<std::string>::iterator marked_it;
  std::unordered_map<std::string, struct docker_api*>::iterator it;

  if (gQueryCache==nullptr) return;

  // Getting entries accessed less than MINTOCLEAN times 
  for (it=gQueryCache->begin(); it!=gQueryCache->end(); it++) { 
    if (it->second->accessed < MINTOCLEAN) {
      markedentries.push_back(it->first);
      free(it->second);
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
/*
 * docker_id_getname - fill a docker_api data structure with information
 *   garthered by a docker daemon query
 * @t_cgroupid: full length container identifier
 * @t_buff: t_dqr docker api query data structure
 * returns 1 if kubernetes informations have been found
 */
int docker_id_get (char* t_cgroupid, docker_api **t_dqr) {
  static time_t last = time(nullptr);
  time_t now = time(nullptr);
  if (difftime(now, last) > 5) {
    clean_cache();
    last = now;
  }

  if (strcmp(t_cgroupid, "") == 0) return -1; 
  
  std::string cgroupid(t_cgroupid);
  docker_api* qr;
  // Checking if the query has been cached. If not then try to update the cache
  if (docker_id_cached(cgroupid, &qr) != 0 && update_query_cache(t_cgroupid, &qr) != 0)  {
    return -1;
  }
  // No error occurred
  *t_dqr = qr;
  return qr->kube;
} 




