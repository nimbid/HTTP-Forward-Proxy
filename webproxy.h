/* =============================== Includes =============================== */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>      
#include <strings.h>     
#include <unistd.h>      
#include <sys/socket.h>  
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>
#include <openssl/md5.h>
#include <signal.h>


/* =============================== Definitions =============================== */
#define MAXLINE  8192              // Maximum text line length.
#define MAX_BUFF_SIZE   8192       // Maximum receive and send buffer size.
#define LISTENQ  1024              // Second argument to listen().

// A structure for building and sending custom HTTP responses.
typedef struct http_response{
  char main[MAX_BUFF_SIZE/2];
  int content_length;
  char message[MAX_BUFF_SIZE];
} http_response_t;

// A structure for received HTTP requests.
typedef struct http_request{
  char *http_method;
  char *host_name;
  unsigned char *hash;
  char *hash_string;
  char *dest_ip;
  char *port;
  int port_val;
  char *directory;
  int conn_fd;
  char *file_type;
  char *file_size;
  char *file_name;
  int is_link_prefetch;
} http_request_t;


/* =============================== Mutexes =============================== */
pthread_mutex_t cache_check_lock;;     // Lock for checking if page is in cache and fresh.
pthread_mutex_t add_cache_entry_lock;  // Lock for adding cache entry.
pthread_mutex_t rem_cache_entry_lock;  // Lock for deleting cache entry.
pthread_mutex_t ip_cache_lock;         // Lock for accessing IP cache.
pthread_mutex_t send_from_cache_lock;  // Lock for sending cached file.
pthread_mutex_t blacklist_lock;        // Lock for accessing blacklist.


/* =============================== Socket-related functions =============================== */

/* Opens a new socket on which proxy
* will listen for new HTTP connections.
* Returns:
*   -> File descriptor of opened socket.
*   -> -1 in case of error.
*/
int open_listen_sock(int port);

/*  Opens a new connection from proxy
*   remote server.
*   Returns:
*     -> File descriptor of new connection.
*     -> -1 in case of errors.
*     -> -2 in case of IP being blacklisted.
*/
int open_remote_conn(struct http_request *request);

/* Checks if given IP is in the blacklist. 
*   Returns:
*     -> 1 if IP is in blacklist.
*     -> 0 if IP is not in blacklist.
*/
int is_ip_blacklisted(char *ip, struct http_request *request);


/* =============================== Thread routines =============================== */

// Thread routine to handle new connections received by the proxy.
void *handle_new_connections(void *vargp);

// Thread routine to spawn new prefetch request-creation threads.
void *handle_prefetch_threads(void *vargp);

// Thread routine to create prefetch request threads.
void *handle_prefetch_requests(void *vargp);


/* =============================== HTTP response builders =============================== */

/*  Builds and sends an HTTP error response
*   of the specified type to the given socket.
*/
void send_http_err_response(struct http_request *request, int type, char *location);

/*  Builds and sends an HTTP 200 OK response
*   to the given socket.
*/
void send_http_ok_response(struct http_request *request);


/* =============================== Core handler functions of proxy =============================== */

/*  Parses HTTP requests received on the listening port and 
*   hands them off to the corresponding thread routine.
*/
void request_handler(int connfd);


/*  Checks if file requested in given HTTP request
*   is in cache and decides further actions.
*/
void check_page_cache(struct http_request *request);

/*  Removes cache entry for given file from cachelist.txt 
*/
void remove_cache_entry(struct http_request *request);

/*  Creates or updates a file entry for given file in cachelist.txt
*/
void add_cache_entry(struct http_request *request);

/*  Fallback function to fetch request from origin server
*   and send to client in case sending from cache fails.
*/
void send_without_caching(struct http_request *request);

/*  Checks cachelist.txt for cache entry and sends the cached file
*   to the client.
*/
void send_cached_page(struct http_request *request);

/*  Fetch requested content from origin server, cache it
*   and then send the cached file.
*/
void cache_and_send(struct http_request *request);

/*  Parse HTML and spawn prefetch request threads.
*/
void generate_prefetch_requests(char *host_name);

/*  Build prefetch requests and hand off to cache handler
*   to decide next steps.
*/
void prefetch_link(char *link);
