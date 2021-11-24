/*
webproxy.c
A basic HTTP webproxy that handles GET requests.
It support multiple simultaenous connections, caching,
and link-prefetching.
Author: Nimish Bhide (University of Colorado, Boulder)
*/

#include "webproxy.h"

int listenfd;               // Proxy's listening socket.
static int cache_TTL;       // Cache time-to-live value in seconds.

/* =============================== Helper funtions =============================== */

/*
*    Removes a line from text file based on
*    the given string argument.
*/
static size_t deleteLine( char* buffer, size_t size, const char* hash_to_delete)
{
    // file format assumed to be as specified in the question i.e. name{space}somevalue{space}someothervalue\n
    // find playerName
    char* p = buffer; 
    bool done = false;
    size_t len = strlen(hash_to_delete);
    size_t newSize = 0;
    do
    {
        char* q = strchr( p, *hash_to_delete ); // look for first letter in playerName
        if ( q != NULL )
        {
        if ( strncmp( q, hash_to_delete, len ) == 0 ) // found name?
        {
            size_t lineSize = 1; // include \n already in line size

            // count number of characters the line has.
            for ( char* line = q; *line != '\n'; ++line) 
            {
            ++lineSize;
            }

            // calculate length left after line by subtracting offsets
            size_t restSize = (size_t)((buffer + size) - (q + lineSize));

            // move block with next line forward
            memmove( q, q + lineSize, restSize );

            // calculate new size
            newSize = size - lineSize;
            done = true;
        }
        else
        {
            p = q + 1; // continue search
        }
        }
        else
        {
        puts( "no such name" );
        done = true;
        }
    }
    while (!done);
    return newSize;
}


/*
*    Drives the deleteLine function defined below.
*/
int deleteLine_helper(char *hash_to_delete)
{
    char file[] = "cachelist.txt";
    struct stat st;
    if ( stat( file, &st ) != -1 )
    {
        // open the file in binary format
        FILE* fp = fopen( file, "rb" );
        if ( fp != NULL )
        {
        // allocate memory to hold file
        char* buffer = malloc( st.st_size ); 

        // read the file into a buffer
        if ( fread(buffer, 1, st.st_size, fp) == st.st_size)
        {
            fclose(fp);

            size_t newSize = deleteLine( buffer, st.st_size, hash_to_delete);

            fp = fopen( file, "wb" );
            if ( fp != NULL )
            {
            fwrite(buffer, 1, newSize, fp);
            fclose(fp);
            }
            else
            {
            perror(file);
            }
        }
        free(buffer);
        }
        else
        {
        perror(file);
        }
    }
    else
    {
        printf( "did not find %s", file );
    }
    return 0;
}



/*
Guard function to look for failures in function calls.
Returns the return value of the called function if 
there is no error, else it exits the program if the called
function returns an error.
*/
static int check(int n, char* err)
{
    if (n == -1)
    {
        perror(err);
        exit(1);
    }
    return n;
}


// SIGINT Handler.
static void sig_handler(int signo)
{
    if((signo == SIGINT) || (signo == SIGTERM))
    {   
        write(STDERR_FILENO, "\nCaught SIGINT!. Closing server.\n", 33);
        close(listenfd);
        exit(EXIT_SUCCESS);
    }
}


/* =============================== MAIN =============================== */

int main(int argc, char **argv)
{
    // Setting up signal handler.
    if (signal(SIGINT, sig_handler) == SIG_ERR)
        exit(EXIT_FAILURE);

    // Check for invalid input from CLI.
    if ((argc != 3) || (atoi(argv[1]) < 5000))
    {   
        // Print out error message explaining correct way to input.
        printf("Invalid input/port.\n");
        printf("Usage --> ./[%s] [Port Number] [Cache TTL]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int *connfdp, srv_port;
    int client_len = sizeof(struct sockaddr_in);
    struct sockaddr_in clientaddr;
    pthread_t thread_id;

    srv_port = atoi(argv[1]); // Get proxy operation port from input.
    cache_TTL = atoi(argv[2]); // Cache TTL input value.

    //Initialise all the mutex locks.
    check(pthread_mutex_init(&cache_check_lock, NULL), "Page cache mutex init failed.\n");
    check(pthread_mutex_init(&ip_cache_lock, NULL), "IP cache mutex init failed.\n");
    check(pthread_mutex_init(&send_from_cache_lock, NULL), "Send from cache mutex init failed.\n");
    check(pthread_mutex_init(&blacklist_lock, NULL), "Blacklist mutex init failed.\n");
    check(pthread_mutex_init(&add_cache_entry_lock, NULL), "Add cache entry mutex init failed.\n");
    check(pthread_mutex_init(&rem_cache_entry_lock, NULL), "Remove cache entry mutex init failed.\n");

    listenfd = open_listen_sock(srv_port);
    while (1)
    {
        // printf("Waiting for a connection on port %d. \r\n", srv_port);
        connfdp = malloc(sizeof(int));
        check(*connfdp = 
                accept(listenfd, (struct sockaddr*)&clientaddr, (socklen_t *)&client_len),
                "Connection accept failed");
        // printf("Got a new connection.\r\n");
        pthread_create(&thread_id, NULL, handle_new_connections, connfdp); // Spawn a new thread to handle request.
    }
}


/* =============================== Thread routines =============================== */

// Thread routine to handle new connections received by the proxy.
void *handle_new_connections(void * vargp)
{
    int connfd = *((int *)vargp);
    request_handler(connfd);
    pthread_detach(pthread_self());
    free(vargp);
    close(connfd);
    return NULL;
}

// Thread routine to spawn new prefetch request-creation threads.
void *handle_prefetch_threads(void *vargp)
{
    char *filename;
    filename = (char *)vargp;
    generate_prefetch_requests(filename);
    pthread_detach(pthread_self());
    free(vargp);
    return NULL;
}

// Thread routine to create prefetch request threads.
void *handle_prefetch_requests(void *vargp)
{
    char *link;
    link = (char *)vargp;
    prefetch_link(link);
    pthread_detach(pthread_self());
    free(vargp);
    return NULL;
}


/* =============================== HTTP response builders =============================== */

// Send HTTP error response based on type.
void send_http_err_response(struct http_request *request, int type, char *location)
{   
    char *err_msg;
    if(type == 400)
        err_msg = "HTTP/1.1 400 Bad Request\n";
    if(type == 403)
        err_msg = "HTTP/1.1 403 Forbidden\n";
    if(type == 404)
        err_msg = "HTTP/1.1 404 Not Found\n";
    if(type == 500)
        err_msg = "HTTP/1.1 500 Internal Server Error\n";
    int len = strlen(err_msg);
    send(request->conn_fd, err_msg, len, MSG_NOSIGNAL);
}


// Send HTTP 200 OK response.
void send_http_ok_response(struct http_request *request)
{
    char *msg;
    msg = "HTTP/1.1 200 OK\n";
    int len = strlen(msg);
    send(request->conn_fd, msg, len, MSG_NOSIGNAL);
}


/* =============================== Socket-related functions =============================== */

// Opens a new port on which proxy server listens for connections.
int open_listen_sock(int port)
{
    int listenfd, optval = 1;
    struct sockaddr_in serveraddr;

    /* Create a socket descriptor */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return -1;

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
                   (const void *)&optval , sizeof(int)) < 0)
        return -1;

    /* listenfd will be an endpoint for all requests to port
       on any IP address for this host */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);
    if (bind(listenfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0)
        return -1;

    /* Make it a listening socket ready to accept connection requests */
    if (listen(listenfd, LISTENQ) < 0)
        return -1;
    return listenfd;
}


// Opens a new connection to the remote server.
int open_remote_conn(struct http_request *request)
{  
    int connectfd, optval=1;
    struct sockaddr_in serveraddr;
    char hostname[strlen(request->host_name)+strlen(request->directory)+5];
    sprintf(hostname,"%s%s",request->host_name,request->directory);

    FILE *f;
    pthread_mutex_lock(&ip_cache_lock);
    f = fopen("ipcache.txt","r");
    if(!f)
    {
        printf("Failed to open IP cache!\n");
        pthread_mutex_unlock(&ip_cache_lock);
        return -1;
    }
    char buf[MAX_BUFF_SIZE];
    char *temp;
    char *to_change;
    char *ip;
    int h_addrtype;
    long h_addr;
    int ip_is_in_cache = 0; // Flag to monitor whether IP is in cache.

    // Find IP address in cache.
    while (fgets(buf, MAX_BUFF_SIZE, f) != NULL)
    {  
        to_change = strtok_r(buf, ":", &temp);
        if (strcmp(to_change, hostname) == 0)
        {   
            ip_is_in_cache = 1;
            ip = strtok_r(NULL, ":", &temp);
            to_change = strtok_r(NULL, ":", &temp);
            serveraddr.sin_family = atoi(to_change);
            to_change = strtok_r(NULL, ":", &temp);
            serveraddr.sin_addr.s_addr = atol(to_change);
            serveraddr.sin_port = htons(request->port_val);
            break;
        }
    }
    fclose(f);
    pthread_mutex_unlock(&ip_cache_lock);
    if(ip_is_in_cache == 0)
    {   
        printf("IP not in cache\n");
        struct hostent *host_entity;
        ip=(char*)malloc(NI_MAXHOST*sizeof(char));
        if((host_entity =  gethostbyname(request->host_name)) == NULL)
        {
            return -1;
        }
        strcpy(ip, inet_ntoa(*(struct in_addr *) host_entity->h_addr));
        request->dest_ip = ip;
        printf("Got remote IP from DNS: %s\n", request->dest_ip);

        // Check if address is in blacklist.
        int is_blisted = is_ip_blacklisted(ip, request);
        if(is_blisted == 1)
        {
            return -2;
        }
    
        //Build the IP socket structure
        serveraddr.sin_family = host_entity->h_addrtype;
        serveraddr.sin_port = htons(request->port_val);
        serveraddr.sin_addr.s_addr = *(long*)host_entity->h_addr;

        // Cache IP address.
        pthread_mutex_lock(&ip_cache_lock);
        f = fopen("ipcache.txt","a");
        if(!f)
        {
            printf("Failed to cache IP address!\n");
            pthread_mutex_unlock(&ip_cache_lock);
            return -1;
        }
        char results[MAXLINE];
        sprintf(results, "%s:%s:%d:%ld\n", hostname, ip, host_entity->h_addrtype, *(long*)host_entity->h_addr);
        fputs(results,f);
        pthread_mutex_unlock(&ip_cache_lock);
        fclose(f);
    }

    // If IP address is not in blacklist, create a new connection with the origin server.

    // Create a socket descriptor.
    check(connectfd = socket(AF_INET, SOCK_STREAM, 0), "Couldn't open socket for conn. to server.\n");

    /* Eliminates "Address already in use" error from bind. */
    if (setsockopt(connectfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(int)) < 0)
        return -1;

    if (inet_pton(AF_INET, ip, &serveraddr.sin_addr) <= 0)
    {
      printf("Invalid/Unsupported Address:%s\n", request->host_name);
      return -1;
    }

    check(connect(connectfd,(struct sockaddr *)&serveraddr,sizeof(serveraddr)), "Failed to connect to remote server.\n");

    if (ip_is_in_cache == 0)
        free(ip);

    return connectfd;
  }


// Checks if given IP address is in the blacklist.
int is_ip_blacklisted(char *ip, struct http_request *request)
{
    FILE *f;
    pthread_mutex_lock(&blacklist_lock);
    f = fopen("blacklist.txt", "r");

    // Check for failure to open file.
    if (!f)
    {   
        pthread_mutex_unlock(&blacklist_lock);
        printf("Couldn't open blacklist file.\r\n");
    }
    char hostname[strlen(request->host_name)+strlen(request->directory)+5];
    sprintf(hostname,"%s%s",request->host_name,request->directory);
    char buf[MAXLINE];
    while (fgets(buf, MAXLINE, f) != NULL)
    {   
        if (strcmp(buf, request->host_name) == 0 || strcmp(buf, ip) == 0)
        {
            printf("Found IP or host in blacklist.\n");
            return 1;
        }
    }
    fclose(f);
    pthread_mutex_unlock(&blacklist_lock);
    return 0;
}


/* =============================== Core handler functions of proxy =============================== */

/* Parses HTTP request received by the proxy on listening port
 * and hands it off to the corresponding thread routine. */
void request_handler(int connfd)
{
    size_t bytes_read;
    char buf[MAXLINE];
    http_request_t request;
    request.conn_fd = connfd;
    
    // In this section of code we read in the request for processing.
    bytes_read = read(connfd, buf, MAXLINE);
    if(bytes_read <= 0)
    {
        send_http_err_response(&request, 400, "No bytes read by request handler.\n");
        return;
    }
    request.is_link_prefetch = 0;

    // Parse HTTP request.
    char *context = NULL;
    // Check if HTTP method is valid- only GET is valid.
    request.http_method = strtok_r(buf, " ", &context);
    if(strstr(request.http_method, "GET") == NULL)
    { 
        // printf("Non GET req detected: %s\n", request.http_method);
        send_http_err_response(&request, 400, "Invalid HTTP method.\n");
        return;
    }

    //Find start of path.
    char *host = strstr(context, "//");
    host = host + 2;
    if(host == NULL)
    {
        send_http_err_response(&request, 400, "Invalid host header.\n");
        return;
    }

    char *portCopy = (char *)malloc(strlen(host)+1*sizeof(char));
    char *port;
    char *directoryCopy = (char *)malloc(strlen(host)+1*sizeof(char));
    char *dir;
    strncpy(portCopy,host,strlen(host));
    strncpy(directoryCopy,host,strlen(host));

    //Find end of host and start of path.
    host = strtok(host, "/");
    if(strstr(host,":")!=NULL)
    {
        host = strtok(host,":");
    }
    request.host_name = host;

    //Decide Port
    port = strtok(portCopy,"/");
    port = strstr(portCopy,":");
    int portVal = 80;
    if(port == NULL)
    {
        port = "80";
    } 
    else 
    {   
        port++; // Move forward by 1 to skip colon.
        portVal = atoi(port);
        if(portVal == 443)
        {
            send_http_err_response(&request, 400, "Port 443 is not supported.\n");
            return;
        }
    }
    //Get the Port Value as an integer
    request.port = port;
    request.port_val = portVal;

    //Get Directory
    dir = strstr(directoryCopy, "/");
    dir = strtok(dir, " ");
    request.directory = dir;
    // printf("%s: %s req detected: %s %s\n", __FUNCTION__, request.http_method, request.host_name, request.directory);


    //For Debugging
    // printf("Request Type: %s\n", request.http_method);
    // printf("Host: %s\n", request.host_name);
    // printf("Port: %s\n", request.port);
    // printf("Directory: %s\n", request.directory);

    //Calculate the md5Hash
    unsigned char result[MD5_DIGEST_LENGTH];
    char hostandDir[strlen(request.host_name)+strlen(request.directory)+5];
    sprintf(hostandDir,"%s%s",request.host_name, request.directory);
    MD5((unsigned char*) hostandDir, strlen(hostandDir), result);
    request.hash = result;

    //Calculate the md5string
    char md5string[33];
    for(int i=0;i<16;i++)
        sprintf(&md5string[i*2],"%02x", (unsigned int)result[i]);
    request.hash_string = md5string;
    request.dest_ip = "";

    // Hand off to the request cache checking function.
    request.file_type = "";
    request.file_size = "";
    check_page_cache(&request);

    free(portCopy);
    free(directoryCopy);

    return;
}


// Checks if given file is in cache and decides next steps.
void check_page_cache(struct http_request *request)
{
    int hash_sum = 0;
    int choice = 0;
    char buf[MAXLINE];
    char *temp_hash;
    char *last_mod_time;
    char *context = NULL;
    int found_file_in_cache = 0;

    // Lock the page cache so that other threads cannot check.
    pthread_mutex_lock(&cache_check_lock);

    FILE *fp;
    fp = fopen("cachelist.txt", "rb");
    while (fgets(buf, MAXLINE, fp) != NULL)
    {  
        temp_hash = strtok_r(buf, " ", &context);
        if (strcmp(temp_hash, request->hash_string) == 0)
        {
            // printf("Found file in cache list\n");
            choice = 2;
            found_file_in_cache = 1;
            strtok_r(NULL, " ", &context);
            strtok_r(NULL, " ", &context);
            strtok_r(NULL, " ", &context);
            last_mod_time = strtok_r(NULL, " ", &context);
            // printf("Last mod time of cached file: %s\n", last_mod_time);
            break;
        }
    }

    if (found_file_in_cache == 0)
    {
        printf("Did not find file %s in cachelist.\n", request->directory);
        choice = 1;
    }
    else
    {   
        char *endptr;
        if (cache_TTL + strtoll(last_mod_time, &endptr, 10) > time(NULL))
        {   
            printf("File found %s in cache and is fresh.\n", request->directory);
            choice = 2;
        }
        else
        {   
            printf("File found %s in cache but is expired.\n", request->directory);
            remove_cache_entry(request);
            choice = 1;
        }
    }

    //Unlock our page cache mutex
    pthread_mutex_unlock(&cache_check_lock);

    //Decide on our action!
    switch (choice)
    {
        case 1:
            printf("Case 1: Fetch from origin.\n");
            cache_and_send(request);
            break;
        case 2:
            printf("Case 2: Send from cache.\n");
            send_cached_page(request);
            break;
        default:
            printf("Error case\n");
            send_http_err_response(request, 500, "Error while checking cache- no choice made");
            break;
    }
    return;
}


// Removes given cache entry from cache list.
void remove_cache_entry(struct http_request *request)
{
    printf("Removing cache entry.\n");
    pthread_mutex_lock(&rem_cache_entry_lock); // Lock cache list before removing entry.
    deleteLine_helper(request->hash_string);
    printf("Cache entry removed.\n");
    pthread_mutex_unlock(&rem_cache_entry_lock); // Unlock cache list mutex.
}


// Adds given file entry to cache list.
void add_cache_entry(struct http_request *request)
{   
    printf("Adding cache entry.\n");
    pthread_mutex_lock(&add_cache_entry_lock); // Lock cache list before adding entry.
    int bytes_written_to_cache;
    char new_entry[(2*strlen(request->hash_string))+60];
    sprintf(new_entry, "%s ./cache/%s.%s %s %s %lld\n", request->hash_string, request->hash_string, strstr(request->file_type,"/")+1, request->file_type, request->file_size, (long long)time(NULL));
    FILE *fptr;
    fptr = fopen("cachelist.txt", "a");
    bytes_written_to_cache = fwrite(new_entry, 1, strlen(new_entry), fptr);
    fclose(fptr);
    printf("Cache entry added\n");
    pthread_mutex_unlock(&add_cache_entry_lock); // Unlock cache list mutex.
}


// Fallback function to fetch content from origin and
// serve it to the client.
void send_without_caching(struct http_request *request)
{
    printf("Sending without caching: %s%s\n", request->host_name,request->directory);
    int http_server_conn = open_remote_conn(request);

    if(http_server_conn == -1)
    {
        close(http_server_conn);
        send_http_err_response(request, 404, "In sendHTTPRequest httpServerConn == -1");
        return;
    }

    if(http_server_conn == -2)
    {
        send_http_err_response(request, 403, "Black Listed Site!");
        return;
    }

    //Let the Server know we've accepted the request.
    send_http_ok_response(request);

    //Craft our request
    char get_request[250];
    sprintf(get_request,"GET %s HTTP/1.1\r\nHost: %s%s\r\n\r\n",request->directory,request->host_name,request->port); //{URL,,host,port}

    int bytes_read = 0;
    char buf[MAX_BUFF_SIZE];
    send(http_server_conn, get_request, strlen(get_request), 0);
    bytes_read = read(http_server_conn, buf, MAXLINE);

    while(bytes_read > 0)
    {
        send(request->conn_fd, buf, bytes_read, MSG_NOSIGNAL);
        bytes_read = read(http_server_conn, buf, MAXLINE);
    }

    if(bytes_read == -1)
    {
        send_http_err_response(request, 500, "In sendHTTPRequest on Read from HTTP Server");
        return;
    }

    // Close the connection with the remote server.
    close(http_server_conn);
    return;
}


void send_cached_page(struct http_request *request)
{   
    printf("Sending cached page: %s%s\n", request->host_name, request->directory);
    char fileBuf[MAX_BUFF_SIZE];
    int bytes_read =0;
    int bytes_sent = 0;
    char buf[MAXLINE];
    char *temp_hash;
    char *context = NULL;

    // Find page in cachelist.txt
    FILE *f;
    FILE *fp;
    char *filetype;
    char *filesize;
    char *file_timestamp;
    char *file_ip;
    pthread_mutex_lock(&send_from_cache_lock);
    f = fopen("cachelist.txt", "rb");
    while (fgets(buf, MAXLINE, f) != NULL)
    {  
        temp_hash = strtok_r(buf, " ", &context);
        if (strcmp(temp_hash, request->hash_string) == 0)
        {   
            fp = fopen(strtok_r(NULL, " ", &context), "rb");
            filetype = strtok_r(NULL, " ", &context);
            filesize = strtok_r(NULL, " ", &context);
            file_timestamp = strtok_r(NULL, " ", &context);
            break;
        }
    }
    if(!fp)
    {
        printf("Can't find file, switching to send without caching!\n");
        send_without_caching(request);
        return;
    }
    fclose(f);

    //Craft HTTP response.
    http_response_t response;
    char temp[MAX_BUFF_SIZE];
    if(strcmp(filesize, "Transfer-Encoding: chunked") == 0)
    {
        sprintf(temp,"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %s\r\n", filetype, filesize);
    }
    else
    {
        sprintf(temp,"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %s\r\n\r\n", filesize, filetype);
    }

    // Send cached file response headers to client.
    strncpy(response.message, temp, strlen(temp));
    // printf("Connfd: %d Sending to browser file: %s\n", request->conn_fd, request->directory);
    bytes_sent = send(request->conn_fd, temp, strlen(temp), MSG_NOSIGNAL);
    
    // Read cached file contents and send body of message.
    while((bytes_read = fread(fileBuf, 1, MAX_BUFF_SIZE, fp)) > 0)
    {   
        // if((bytes_sent = send(request->conn_fd, fileBuf, bytes_read, MSG_NOSIGNAL)) < 0)
        bytes_sent = send(request->conn_fd, fileBuf, bytes_read, MSG_NOSIGNAL);
        // printf("Bytes sent: %d\n", bytes_sent);
        if (bytes_sent < 0)
        { 
            send_http_err_response(request, 500, "Failed to send cached file");
            printf("Failed in:%s%s\n",request->host_name,request->directory);
            break;
        }
    }
    // printf("Cached file completely sent.\n");
    fclose(fp);
    pthread_mutex_unlock(&send_from_cache_lock);
    return;
}


void cache_and_send(struct http_request *request)
{
    //Establish a connection with the origin HTTP Server
    int http_server_conn = open_remote_conn(request);
    if(http_server_conn == -1)
    {
        close(http_server_conn);
        send_http_err_response(request, 404, "In sendHTTPRequest httpServerConn == -1");
        return;
    }
    if(http_server_conn == -2)
    {
        send_http_err_response(request, 403, "Black Listed Site!");
        return;
    }

    //Craft and send HTTP request to origin.
    char get_request[250];
    sprintf(get_request,"GET %s HTTP/1.1\r\nHost: %s%s\r\n\r\n", request->directory, request->host_name, request->port);
    FILE *f;
    char filename[strlen(request->hash_string)+40];
    char *filetype;
    char *filesize;
    char *temp_buff;
    int bytes_read;
    size_t toReadAfter = 0;
    char buf[MAX_BUFF_SIZE]="";
    char head[MAX_BUFF_SIZE]="";
    char another[MAX_BUFF_SIZE];
    char *temp;
    char *headTemp;
    write(http_server_conn, get_request, strlen(get_request));
    // printf("Sending request to remote for: %s\n", request->directory);

    // Define flags for parsing response from origin.
    int chunk = 0;
    int not_old_headers = 1;
    int image = 0;
    int has_both = 0;
    int is_html = 0;
    int resp_not_200 = 0;

    // Read in the HTTP header. 
    bytes_read = read(http_server_conn, buf, MAXLINE);
    // printf("Got %d bytes from remote for request: %s ; is prefetch = %d\n", bytes_read, request->directory, request->is_link_prefetch);

    if(request->is_link_prefetch == 1)
    {
        if(strstr(buf,"HTTP/1.1 301 TLS Redirect") != NULL)
        return;
    }
    memcpy(head, buf, sizeof(buf));
    // printf("Received HTTP headers: %s\n", head);
    if (strstr(head, "HTTP/1.1 200") == NULL)
    {
        resp_not_200 = 1;
    }

    //Get Content-Length
    if(strstr(head,"Content-Length:")!=NULL)
    {
        temp=(char *)malloc(strlen(buf)+1*sizeof(char));
        strcpy(temp,head);
        filesize = strstr(temp,"Content-Length:");
        filesize = filesize + 16;
        filesize = strtok(filesize,"\r\n");
        request->file_size = (char *)malloc(strlen(filesize)+1*sizeof(char));
        strcpy(request->file_size, filesize);
        free(temp);
    }

    //Check if it's chunked!
    if(strstr(head,"Transfer-Encoding: chunked") != NULL)
    {
        chunk = 1;
        printf("Chunked detected\n");
        char c[]="Transfer-Encoding: chunked";
        request->file_size = (char *)malloc(strlen(c)+1*sizeof(char));
        strncpy(request->file_size,c,strlen(c));
    }

    //Get the Content Type
    if(strstr(head,"Content-Type:") != NULL)
    {
        temp=(char *)malloc(strlen(buf)+1*sizeof(char));
        strcpy(temp,head);
        filetype = strstr(temp,"Content-Type:");
        filetype = filetype + 14;
        filetype = strtok(filetype,"\r\n");
        request->file_type = (char *)malloc(strlen(filetype)+1*sizeof(char));
        strcpy(request->file_type, filetype);
        free(temp);
        // printf("Found file type: %s for %s\n", request->file_type, request->directory);
        if(strstr(request->file_type, "image") != NULL)
        {
            image = 1;
        } 
        else if(strstr(request->file_type, ";") != NULL)
        {
            strtok(request->file_type,";");
        }
        //Link PreFetching!
        if(strstr(request->file_type,"html") != NULL)
        {
            is_html = 1;
        }
    }

    // Look for no response.
    if(request->file_size == NULL || request->file_type == NULL)
    {
        send_http_err_response(request, 400, "NULL filesize and filetype");
        return;
    }

    sprintf(filename, "./cache/%s.%s", request->hash_string, strstr(request->file_type,"/")+1);
    request->file_name = filename;
    add_cache_entry(request);
    f = fopen(filename,"wb");
    if(!f)
    {
        printf("Can't cache, getting file from remote server.\n");
        if(request->is_link_prefetch == 0)
        {
            send_without_caching(request);
        }
        return;
    }

    memcpy(another,head,sizeof(head));
    temp_buff = strstr(another,"\r\n\r\n");
    for (int i = 0; i < 4; i++)
    {
        temp_buff++;
        if (temp_buff == NULL)
            break;
    }

    if(temp_buff != NULL) 
    {
        toReadAfter=(size_t)(temp_buff - another);
        headTemp = &buf[toReadAfter];
    }
    fwrite(headTemp, bytes_read - toReadAfter, 1, f);
    while((resp_not_200 == 0) && (bytes_read = read(http_server_conn, buf, MAXLINE)) > 0)
    {   
        // printf("Writing bytes to cache for %s\n", request->directory);
        fwrite(buf, 1, bytes_read, f);
        if(chunk == 1 && strstr(buf,"\r\n0\r\n") != NULL)
            break;
        bzero(buf, MAX_BUFF_SIZE);
    }
    fclose(f);
    close(http_server_conn);
    if(bytes_read == -1)
    {
        send_http_err_response(request, 500, "In sendHTTPRequest on Read from HTTP Server");
        return;
    }

    // If link is HTML and is not prefetched, then spawn a prefetch thread.
    if(is_html == 1 && request->is_link_prefetch == 0 && resp_not_200 == 0)
    {
        //Do link PreFetching
        char websiteFileName[200];
        sprintf(websiteFileName,"%s:%s",request->host_name,request->file_name);
        pthread_t tid;
        char *fn;
        fn = (char *)malloc(strlen(websiteFileName)+1*sizeof(char));
        strcpy(fn, websiteFileName);
        printf("Starting prefetch thread for: %s%s\n", request->host_name, request->directory);
        pthread_create(&tid, NULL, handle_prefetch_threads, fn);
    }

    // If the link is not prefetched, send from cache.
    if(request->is_link_prefetch == 0)
    {   
        printf("Link not prefetched and not html: Sending file descriptor %d to send_cached_page\n", request->conn_fd);
        send_cached_page(request);
    }

    return;
}


// Parses html and creates new prefetch threads.
void generate_prefetch_requests(char *host_name)
{   
    printf("Generating prefetch for: %s\n", host_name);
    char *filename;
    strtok_r(host_name, ":", &filename);
    FILE *f;
    char fileBuf[MAX_BUFF_SIZE];

    f = fopen(filename,"r");
    if(!f)
    {
        printf("Link linkPreFetchThreadCreator Failed!\n");
        return;
    }

    // Parse the HTML to find prefetch links.
    char *token;
    char website_name[200];
    pthread_t tid;
    char *fn;
    while(fgets(fileBuf,MAX_BUFF_SIZE,f) != NULL)
    {
        if(strstr(fileBuf,"href") != NULL)
        {
            if(strstr(fileBuf,"<a") || strstr(fileBuf,"</a>"))
            {
                if(strstr(fileBuf,"http") == NULL)
                {
                    token = strstr(fileBuf,"href=" )+strlen("href=")+1;
                    token = strtok(token,"\"");
                    if(strcmp(token,"#") != 0)
                    {
                        sprintf(website_name,"%s/%s",host_name,token);
                        fn = (char *)malloc(strlen(website_name)+1*sizeof(char));
                        strcpy(fn,website_name);
                        pthread_create(&tid, NULL, handle_prefetch_requests, fn);
                    }
                }
                else 
                {
                    if(strstr(fileBuf,"https") == NULL)
                    {
                        token = strstr(fileBuf,"//")+strlen("//");
                        token = strtok(token,"\"");
                        fn = (char *)malloc(strlen(token)+1*sizeof(char));
                        strcpy(fn,token);
                        pthread_create(&tid, NULL, handle_prefetch_requests, fn);
                    }
                }
            }
        }
    }
    fclose(f);
}


// Build prefetch requests and hand off to cache handlerto decide next steps.
void prefetch_link(char *link)
{   
    printf("Prefetching link: %s\n", link);
    char *directory;
    strtok_r(link,"/",&directory);
    http_request_t temp;
    temp.host_name = link;
    char dir[strlen(directory)+5];
    sprintf(dir,"/%s",directory);
    temp.directory = dir;
    temp.port_val = 80;
    temp.port = "";

    // Calculate the md5Hash
    unsigned char result[MD5_DIGEST_LENGTH];
    char hostandDir[strlen(temp.host_name)+strlen(temp.directory)+5];
    sprintf(hostandDir,"%s%s",temp.host_name, temp.directory);
    MD5((unsigned char*) hostandDir, strlen(hostandDir), result);
    temp.hash = result;

    // alculate the md5string
    char md5string[33];
    for(int i=0;i<16;i++)
        sprintf(&md5string[i*2],"%02x", (unsigned int)result[i]);
    temp.hash_string = md5string;
    temp.dest_ip = "";

    // Set other request attributes and hand off to cache-checker.
    temp.file_type = "";
    temp.file_size = "";
    temp.is_link_prefetch = 1;
    check_page_cache(&temp);
    return;
    }
