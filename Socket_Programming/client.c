#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SERVER_PORT 50000
#define BUFLEN 1024

void print_socket_response(int);

int main(int argc, char **argv)
{
  int sd, port;
  struct sockaddr_in server;
  char *host, buf[BUFLEN];
  int bytes_received;

  // #0. 입력 처리
  switch (argc)
  {
  case 2:
    host = argv[1];
    port = SERVER_PORT;
    break;
  case 3:
    host = argv[1];
    port = atoi(argv[2]);
    break;
  default:
    fprintf(stderr, "Usage: %s host [port]\n", argv[0]);
    exit(1);
  }

  // printf("host: %s, port: %d", host, port);
  // #1. 소켓 생성
  if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
  {
    fprintf(stderr, "Can't create a socket\n");
    exit(1);
  }

  // #2. 서버 주소 설정
  memset(&server, '0', sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = inet_addr(host);
  server.sin_port = htons(SERVER_PORT);

  // #3. IPv4 주소 변환
  if (inet_pton(AF_INET, host, &server.sin_addr) <= 0)
  {
    perror("Invalid address/ Address not supported");
    return 1;
  }

  // #4. 서버에 연결 요청
  if (connect(sd, (struct sockaddr *)&server, sizeof(server)) == -1)
  {
    fprintf(stderr, "Connecting Server Failed\n");
    exit(1);
  }

  printf("연결 성공!\n");
  // #5. First Stage (Initial Message 수신)
  // #5.1 Bug 연결 그림
  print_socket_response(sd);
  // #5.2 학번
  memset(buf, 0x00, BUFLEN);
  read(0, buf, BUFLEN); // ID 입력

  write(sd, buf, strlen(buf)); // ID 보내기
  print_socket_response(sd);   // Your Id is 2019311945

  // #5.3 ServerIP
  memset(buf, 0x00, BUFLEN);
  read(0, buf, sizeof(buf)); // 0: stdin
  write(sd, buf, strlen(buf));
  print_socket_response(sd);

  // 5.3 Port
  memset(buf, 0x00, BUFLEN);
  read(0, buf, sizeof(buf)); // 0: stdin
  write(sd, buf, strlen(buf));
  print_socket_response(sd);

  // 5.4 Confirm Yes/No & OK
  memset(buf, 0x00, BUFLEN);
  read(0, buf, sizeof(buf)); // 0: stdin
  write(sd, buf, strlen(buf));
  print_socket_response(sd);
  memset(buf, 0x00, BUFLEN);
  read(0, buf, sizeof(buf)); // 0: stdin
  write(sd, buf, strlen(buf));
  print_socket_response(sd);
  memset(buf, 0x00, BUFLEN);
  read(0, buf, sizeof(buf)); // 0: stdin
  write(sd, buf, strlen(buf));
  print_socket_response(sd);

  // #6. TA의 CLIENT로부터 5개의 RANDOM DATA 받기

  // 소켓 닫기
  close(sd);

  return 0;
}

void print_socket_response(int sd)
{
  int readLen;
  char buf[BUFLEN];

  memset(buf, 0x00, BUFLEN);
  readLen = read(sd, buf, BUFLEN);
  if (readLen > 0)
  {
    printf("%s", buf);
  }
  else if (readLen == 0)
  {
    printf("Server closed connection\n");
  }
  else
  {
    perror("Read error");
  }
  memset(buf, 0x00, BUFLEN);
  readLen = read(sd, buf, BUFLEN);
  if (readLen > 0)
  {
    printf("%s", buf);
  }
  else if (readLen == 0)
  {
    printf("Server closed connection\n");
  }
  else
  {
    perror("Read error");
  }
}