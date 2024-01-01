/*
 * friendlist.c - [Starting code for] a web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University
 * 
 * Completed by Alex Cao for CS4400, Fall 2023, University of Utah
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

static void doit(int fd);
static dictionary_t *read_requesthdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum, 
                        char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);
static void serve_request(int fd, dictionary_t *query);
static void serve_greet(int fd, dictionary_t *query);
static void serve_friends(int fd, dictionary_t *query);
static void serve_befriend(int fd, dictionary_t *query);
static void serve_unfriend(int fd, dictionary_t *query);
static void serve_introduce(int fd, dictionary_t *query);
void *thread(void *vargp);
static dictionary_t *friendsDict;
pthread_mutex_t lock;

int main(int argc, char **argv) {
  int listenfd, *connfd;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;
  pthread_t tid;


  /* Check command line args */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }

  listenfd = Open_listenfd(argv[1]);

  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);
  pthread_mutex_init(&lock, NULL);
  friendsDict = make_dictionary(COMPARE_CASE_SENS, free);
  while (1) {
    clientlen = sizeof(clientaddr);
    connfd = Malloc(sizeof(int));

    *connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (connfd >= 0) {
      Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, 
                  port, MAXLINE, 0);
      pthread_create(&tid, NULL, thread, connfd);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
    }
  }
}
void *thread(void *varpg){
  //printf("created a new thread\n");
  int connfd = *((int*)varpg);
  pthread_detach(pthread_self());
  free(varpg);
  doit(connfd);
  Close(connfd);
  return NULL;
}

/*
 * doit - handle one HTTP request/response transaction
 */
void doit(int fd) {
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return;
  printf("%s", buf);
  
  if (!parse_request_line(buf, &method, &uri, &version)) {
    clienterror(fd, method, "400", "Bad Request",
                "Friendlist did not recognize the request");
  } else {
    if (strcasecmp(version, "HTTP/1.0")
        && strcasecmp(version, "HTTP/1.1")) {
      clienterror(fd, version, "501", "Not Implemented",
                  "Friendlist does not implement that version");
    } else if (strcasecmp(method, "GET")
               && strcasecmp(method, "POST")) {
      clienterror(fd, method, "501", "Not Implemented",
                  "Friendlist does not implement that method");
    } else {
      headers = read_requesthdrs(&rio);

      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST"))
        read_postquery(&rio, headers, query);

      /* For debugging, print the dictionary */
      print_stringdictionary(query);

      /* You'll want to handle different queries here,
         but the intial implementation always returns
         nothing: */
      
      if (starts_with("/friends", uri))
        serve_friends(fd, query);
      else if(starts_with("/befriend", uri)){
        serve_befriend(fd, query);
      }
      else if(starts_with("/unfriend", uri)){
        serve_unfriend(fd, query);
      }
      else if(starts_with("/introduce", uri)){
        serve_introduce(fd, query);
      }
      else 
      printf("default response\n");
        serve_request(fd, query);
      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
    }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp) {
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, NULL);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while(strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }
  
  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest) {
  char *len_str, *type, *buffer;
  int len;
  
  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");
  
  buffer = malloc(len+1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded")) {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type) {
  char *len_str, *header;
  
  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: Friendlist Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

/*
 * serve_request - example request handler
 */
static void serve_request(int fd, dictionary_t *query) {
  size_t len;
  char *body, *header;

  body = strdup("alice\nbob");

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

static void serve_friends(int fd, dictionary_t *query){
  size_t len;
  char *body, *header;

  char* user = dictionary_get(query, "user");
  pthread_mutex_lock(&lock);
  dictionary_t *userFriends = dictionary_get(friendsDict, user);
  char* userFriendString;
  
  if (userFriends != NULL){
    userFriendString = join_strings(dictionary_keys(userFriends), '\n');
  }
  else
  {
    userFriendString = "";
  }
  pthread_mutex_unlock(&lock);
  body = strdup(userFriendString);

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

static void serve_unfriend(int fd, dictionary_t *query){
  size_t len;
  char *body, *header;
 
  if(query == NULL){
    clienterror(fd, "POST", "400", "Bad Request", "query is NULL");
    return;
  }

  char* user = dictionary_get(query, "user");
  char* friends = dictionary_get(query, "friends");

  if(!user || ! friends){
    clienterror(fd, "POST", "400", "Bad Request","user or friends is empty");
    return;
  }

  pthread_mutex_lock(&lock);

  dictionary_t *userFriendList = dictionary_get(friendsDict, user);
  dictionary_t *currFriends;

  //check if user are in friend dictionary
  if(userFriendList == NULL){
    
    clienterror(fd, "POST", "400", "Bad Request", "unfriend user not in dictionary");
    return;
  }
  else{
    //get the friend list
    userFriendList = dictionary_get(friendsDict, user);
  }

  char **friendEntries = split_string(friends,'\n');
  int i;
  if(friendEntries == NULL){

    clienterror(fd, "POST", "400", "Bad Request", "friends is NULL");
  }


  //Add friends 
  for (i = 0; friendEntries[i]!= NULL; ++i)
  {
    //can't remove user itself as its new friend
    if(strcmp(user, friendEntries[i]) == 0){
        continue;
    }

    currFriends = dictionary_get(friendsDict, friendEntries[i]);
    //friend not in dictionary
    if (currFriends == NULL){
      continue;
    } 

    // if user's friendlist does have this old friend, remove it 
    dictionary_remove(userFriendList, friendEntries[i]);
    
    // if friend does has user as friend, remove it
    dictionary_remove(currFriends, user);
  }
  
  char* friendListString;
  friendListString = join_strings(dictionary_keys(userFriendList), '\n');
  pthread_mutex_unlock(&lock);
 
  body = strdup(friendListString);
  len = strlen(body);
  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);

}

static void serve_befriend(int fd, dictionary_t *query){
  size_t len;
  char *body, *header;
 
  if(query == NULL){
    clienterror(fd, "POST", "400", "Bad Request", "query is NULL");
    return;
  }
  
  char* user = dictionary_get(query, "user");
  char* friends = dictionary_get(query, "friends");
  
  if(!user || ! friends){
    clienterror(fd, "POST", "400", "Bad Request","user or friends is empty");
    return;
  }
  
  pthread_mutex_lock(&lock);
  dictionary_t *userFriendList = dictionary_get(friendsDict, user);
  dictionary_t *currFriends;

  //check if user are in friend dictionary

  if((userFriendList) == NULL){
    //initialize user's friend list
    userFriendList = make_dictionary(COMPARE_CASE_SENS, free);
    dictionary_set(friendsDict, user, userFriendList);
  }

  char **friendEntries = split_string(friends,'\n');
  

  if(friendEntries == NULL){
    clienterror(fd, "POST", "400", "Bad Request", "friends is NULL");
  }

  int i;
  //Add friends 
  for (i = 0; friendEntries[i]!= NULL; ++i)
  {
    //can't add user itself as its new friend
    if(strcmp(user, friendEntries[i]) == 0){
        continue;
    }

    //new friend not in dictionary
    currFriends = dictionary_get(friendsDict, friendEntries[i]);
    if (currFriends == NULL){
      currFriends = make_dictionary(COMPARE_CASE_SENS, free);
      dictionary_set(friendsDict, friendEntries[i], currFriends);
    }

    // if user's friendlist does not have this new friend, add it
    if(dictionary_get(userFriendList, friendEntries[i]) == NULL){
      dictionary_set(userFriendList, friendEntries[i], NULL);
    }


    // if new friend does not has user as friend, add it
    if(dictionary_get(currFriends, user) == NULL){
      dictionary_set(currFriends, user, NULL);
    }

  }
  

  char* friendListString;
  friendListString = join_strings(dictionary_keys(userFriendList), '\n');
  pthread_mutex_unlock(&lock);
  
  body = strdup(friendListString);
  len = strlen(body);
  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}
static void serve_introduce(int fd, dictionary_t *query){
  size_t len;
  char *body, *header;
  rio_t rio;

  //printf("introducing\n");
  if(query == NULL){
    clienterror(fd, "POST", "400", "Bad Request", "query is NULL");
    return;
  }

  char* user = dictionary_get(query, "user");
  char* friend = dictionary_get(query, "friend");
  char* host = dictionary_get(query, "host");
  char* port = dictionary_get(query, "port");

  if(!user||!friend||!host||!port){
    clienterror(fd, "POST", "400", "Bad Request","Some arguments in four are empty");
    return;
  }
  
  int connfd;

  //socket for read and write
  connfd = Open_clientfd(host, port);

  // format the request
  friend = query_encode(friend);
  char* request = append_strings("GET /friends?user=", friend," HTTP/1.1\r\n\r\n", NULL);
  

  // send request to other server or concurrent server
  Rio_writen(connfd, request, strlen(request));
  Rio_readinitb(&rio, connfd);


  char readBuf[MAXLINE];
  if(Rio_readlineb(&rio, readBuf, MAXLINE) <= 0){
    clienterror(fd, "POST", "400", "Bad Request", "failed to read from server.");
    return;
  }

  char *version; 
  char *status; 
  char *desc;
  parse_status_line(readBuf, &version, &status, &desc);

  if(strcmp(status, "200") || strcmp(desc, "OK")){
    clienterror(fd, status, "501", "Not Implemented", "recieved not 200 or OK from server.");
    return;
  }
  
  dictionary_t * headers = read_requesthdrs(&rio);
  char* lengthString = dictionary_get(headers, "Content-length");
  int length = atoi(lengthString);

  //read respond back from the server
  char buffer[MAXLINE];
  char newBuffer[length];

  //temporary solution to aviod a extra unknown charactar in simple test
  if(length >= MAXLINE){
    Rio_readnb(&rio, newBuffer, length);
  }
  else{
    Rio_readnb(&rio, buffer, length);
  }
  
  Shutdown(connfd, SHUT_WR);

  pthread_mutex_lock(&lock);

  dictionary_t *userFriendList = dictionary_get(friendsDict, user);
  dictionary_t *currFriends;

  //check if user are in friend dictionary
  if(userFriendList == NULL){
    //initialize friend list
    userFriendList = make_dictionary(COMPARE_CASE_SENS, free);
    dictionary_set(friendsDict, user, userFriendList);
  }
  char **friendEntries;
  if(length >= MAXLINE){
    friendEntries = split_string(newBuffer,'\n');
  }
  else{
    friendEntries = split_string(buffer,'\n');
  }
  
  int i;
  if(friendEntries == NULL){

    clienterror(fd, "POST", "400", "Bad Request", "friends is NULL");
  }

  //Add friends 
  for (i = 0; friendEntries[i]!= NULL; ++i)
  {

    //can't add user itself as its new friend
    if(strcmp(user, friendEntries[i]) == 0){
        continue;
    }

    currFriends = dictionary_get(friendsDict, friendEntries[i]);
    //new friend not in dictionary
    if (currFriends == NULL){
      currFriends = make_dictionary(COMPARE_CASE_SENS, free);
      dictionary_set(friendsDict, friendEntries[i], currFriends);
    }
   

    // if user's friendlist does not have this new friend, add it
    if(dictionary_get(userFriendList, friendEntries[i]) == NULL){
      dictionary_set(userFriendList, friendEntries[i], NULL);
    }


    // if new friend does not has user as friend, add it
    if(dictionary_get(currFriends, user) == NULL){
      dictionary_set(currFriends, user, NULL);
    }
  }
  pthread_mutex_unlock(&lock);

  body = strdup("");
  len = strlen(body);
  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);
  
  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
  Close(connfd);
}
// for lab
static void serve_greet(int fd, dictionary_t *query){
  size_t len;
  char *body, *header;

  char* user = dictionary_get(query, "user");

  //body = strdup("Greetings!");
  body = append_strings("Greetings, ", user, "!", NULL);

  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  /* Send response body to client */
  Rio_writen(fd, body, len);

  free(body);
}

/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg) {
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Friendlist Error</title>",
                        "<body bgcolor=""ffffff"">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>Friendlist Server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);
  
  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d) {
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++) {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}
