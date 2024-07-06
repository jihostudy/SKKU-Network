#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>

#define SERVER_PORT 4296
#define BUFLEN 1024
#define MAX_CLIENTS 3

void handle_client(int client_socket);

// 자식 프로세스가 종료될 때 호출되어 좀비 프로세스를 방지
void sigchld_handler(int s)
{
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;
}

int main()
{
  int server_socket, client_socket;
  struct sockaddr_in server_addr, client_addr;
  socklen_t addr_len = sizeof(client_addr);
  struct sigaction sa;
  pid_t pid;

  // #1. 서버 소켓 생성
  if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0)
  {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  // #2. 서버 주소 설정
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(SERVER_PORT);

  // #3. 소켓에 주소 할당
  if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
  {
    perror("bind failed");
    close(server_socket);
    exit(EXIT_FAILURE);
  }

  // #4. 연결 대기
  if (listen(server_socket, MAX_CLIENTS) < 0)
  {
    perror("listen");
    close(server_socket);
    exit(EXIT_FAILURE);
  }

  printf("Listening on port %d\n", SERVER_PORT);

  // #5. 좀비 프로세스를 방지하기 위해 SIGCHLD 시그널 처리
  sa.sa_handler = sigchld_handler; // 핸들러 설정
  sigemptyset(&sa.sa_mask);        // 시그널 마스크 초기화
  sa.sa_flags = SA_RESTART;        // 시그널 핸들러가 중단된 시스템 호출을 재시작하도록 설정
  if (sigaction(SIGCHLD, &sa, NULL) == -1)
  { // SIGCHLD 시그널에 대해 핸들러 등록
    perror("sigaction");
    exit(EXIT_FAILURE);
  }

  while (1)
  {
    printf("\n*****server waiting for new client connection:*****\n");
    // #6. 새로운 연결 처리
    if ((client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len)) < 0)
    {
      perror("accept");
      continue;
    }

    printf("New connection, socket fd is %d, ip is : %s, port : %d\n",
           client_socket, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // #7. 새로운 프로세스 생성
    pid = fork();
    if (pid == 0)
    {                               // 자식 프로세스
      close(server_socket);         // 자식 프로세스는 서버 소켓을 닫음
      handle_client(client_socket); // 클라이언트 요청 처리
      close(client_socket);         // 처리 후 클라이언트 소켓을 닫음
      exit(0);                      // 자식 프로세스 종료
    }
    close(client_socket); // 부모 프로세스는 클라이언트 소켓을 닫음
  }

  return 0;
}

void handle_client(int client_socket)
{
  char buffer[BUFLEN];
  int readLen;
  // Buffer Flush 필요 x (길지 않음)
  while ((readLen = read(client_socket, buffer, BUFLEN)) > 0)
  {
    buffer[readLen] = '\0';
    printf("Received: %s\n", buffer);
    // write(client_socket, "Data received\n", 14);
  }

  if (readLen == 0)
  {
    printf("Client disconnected\n");
  }
  else if (readLen < 0)
  {
    perror("read error");
  }
}
