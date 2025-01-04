#include <stdio.h> // for printf
#include <sys/socket.h> // for socket, PF_NET, SOCK_STREAM
#include <string.h> // for strerror, memset
#include <errno.h> // for errno
#include <arpa/inet.h> // for struct sockaddr_in, htonl, INADDR_ANY, htons
#include <unistd.h> // for close
#include <libgen.h> // for dirname
#if defined(ENABLE_SSL)
#include <openssl/ssl.h> // SSL_load_error_strings, SSL_library_init
#endif

int main(int argc, char *argv[]) {
  // Get program file path.
  char programPath[256];
  memset(programPath, 0, sizeof(programPath));
  char link[256];
  memset(link, 0, sizeof(link));
  snprintf(link, 256, "/proc/%d/exe", getpid());
  if (readlink(link, programPath, sizeof(programPath)) == - 1) {
    printf("read program path error: %s\n", strerror(errno));
    goto EXIT;
  }
  printf("program path = %s\n", dirname(programPath));
  
#if defined(ENABLE_SSL)
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_algorithms();

  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  SSL_CTX_use_certificate_file(ctx, "/path/to/certificate/file", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "/path/to/privatekey/file", SSL_FILETYPE_PEM);
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
#endif
  
  // Create socket.
  int sockfd = socket(PF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    printf("socket error: %s\n", strerror(errno));
    goto EXIT;
  }

  // Bind socket.
  struct sockaddr_in server;
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_ANY);
#if defined(ENABLE_SSL)
  server.sin_port = htons(443);
#else
  server.sin_port = htons(80);
#endif
  if (bind(sockfd, (struct sockaddr*)&server, sizeof(server)) == -1) {
    printf("bind error: %s\n", strerror(errno));
    goto EXIT;
  }

  // Set listening value.
  if (listen(sockfd, 5) == -1) {
    printf("listen error: %s\n", strerror(errno));
    goto EXIT;
  }

  while (1) {
    // Listen for clients.
    struct sockaddr_in client;
    memset(&client, 0, sizeof(client));
    int size = sizeof(client);
    int cfd = accept(sockfd, (struct sockaddr*)&client, &size);

    if (cfd == -1) {
      printf("accept error: %d\n", strerror(errno));
      break;
    }

#if defined(ENABLE_SSL)
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, cfd);
    int ret = SSL_accept(ssl);
    if (ret != 1) {
      printf("ssl accept error: %d\n", SSL_get_error(ssl, ret));
      continue;
    }
#endif

    // Recieve request data.
    char request[1024];
    memset(request, 0, sizeof(request));
    int rsize;
#if defined(ENABLE_SSL)
    rsize = SSL_read(ssl, request, sizeof(request));
#else
    rsize = recv(cfd, request, sizeof(request), 0);
#endif
    if (rsize == 0) {
      printf("connection ended\n");
#if defined(ENABLE_SSL)
      int sd = SSL_get_fd(ssl);
      SSL_free(ssl);
      close(sd);
#endif
      close(cfd);
      break;
    }

    printf("request message size: %d\n", rsize);
    printf("%s\n", request);

    // Slice the first line of request.
    char *line = strtok(request, "\n");
    // Slice the first token of the first line.
    char *t1 = strtok(line, " ");
    if (t1 == NULL) {
      printf("no method error\n");
#if defined(ENABLE_SSL)
      int sd = SSL_get_fd(ssl);
      SSL_free(ssl);
      close(sd);
#endif
      close(cfd);
      continue;
    }
    char method[5];
    memset(method, 0, sizeof(method));
    strncpy(method, t1, sizeof(method));
    // Slice the second token of the first line.
    char *t2 = strtok(NULL, " ");
    if (t2 == NULL) {
      printf("no target error\n");
#if defined(ENABLE_SSL)
      int sd = SSL_get_fd(ssl);
      SSL_free(ssl);
      close(sd);
#endif
      close(cfd);
      continue;
    }
    char target[256];
    memset(target, 0, sizeof(target));
    strncpy(target, t2, sizeof(target));

    // Parse for request.
    char header[64];
    char body[512];
    char path[512];
    memset(path, 0, sizeof(path));
    int status;
    if (strcmp(method, "GET") == 0) {
      if (strcmp(target, "/") == 0) {
        snprintf(path, sizeof(path), "%s/data/index.html", programPath);
      } else {
        snprintf(path, sizeof(path), "%s%s", programPath, target);
      }
      int fsize = 0;
      FILE *f = fopen(path, "rb");
      printf("path = %s\n", path);
      printf("errno = %s\n", strerror(errno));
      if (f != NULL) {
        int s = 0;
        do {
          s = fread(body, 1, sizeof(body), f);
          fsize += s;
        } while (s != 0);
        fclose(f);
        printf("fsize = %d\n", fsize);
      }
      if (fsize == 0) {
        status = 404;
      } else {
        f = fopen(path, "r");
        memset(body, 0, sizeof(body));
        fread(body, 1, fsize, f);
        fclose(f);
        status = 200;
      }
    } else {
      status = 404;
    }

    // Send the response.
    memset(header, 0, sizeof(header));
    sprintf(header, "Content-Length: %d\r\n", strlen(body));
    char response[1024];
    memset(response, 0, sizeof(response));
    if (status == 200) {
      sprintf(response, "HTTP/1.1 200 OK\r\n%s\r\n", header);
      memcpy(&response[strlen(response)], body, strlen(body));
    } else {
      sprintf(response, "HTTP/1.1 404 Not Found\r\n%s\r\n", header);
    }
    int ssize;
#if defined(ENABLE_SSL)
    ssize = SSL_write(ssl, response, strlen(response));
#else
    ssize = send(cfd, response, strlen(response), 0);
#endif
    printf("send size=%d\n", ssize);

#if defined(ENABLE_SSL)
    int sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
#endif
    
    // Close client socket.
    close(cfd);
  }

EXIT:
#if defined(ENABLE_SSL)
  SSL_CTX_free(ctx);
#endif

  // Close socket.
  close(sockfd);

  return -1;
}
