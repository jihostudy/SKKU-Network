#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#define SERVER_TCP_PORT 3000
#define BUFLEN 256
int main(int argc, char **argv)
{
   int n, bytes_to_read;
   int sd, port;
   struct hostent *hp;
   struct sockaddr_in server;
   char *host, *bp, rbuf[BUFLEN], sbuf[BUFLEN];
   switch (argc)
   {
   case 2: // 서버 포트 지정X
      host = argv[1];
      port = SERVER_TCP_PORT;
      printf("Host: %d, port : %d\n", host, port);
      break;
   case 3: // 서버 포트 지정
      host = argv[1];
      port = atoi(argv[2]);
      break;
   default:
      fprintf(stderr, "Usage: %s host [port]\n", argv[0]);
      exit(1);
   }

   // #1. 소켓 생성
   if ((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
   {
      fprintf(stderr, "Can't create a socket\n");
      exit(1);
   }
   bzero((char *)&server, sizeof(struct sockaddr_in));
   server.sin_family = AF_INET;
   server.sin_port = htons(port);
   if ((hp = gethostbyname(host)) == NULL)
   {
      fprintf(stderr, "Can't get server's address\n");
      exit(1);
   }
   bcopy(hp->h_addr, (char *)&server.sin_addr, hp->h_length);
   /* Connecting to the server */
   if (connect(sd, (struct sockaddr *)&server,
               sizeof(server)) == -1)
   {
      fprintf(stderr, "Can't connect\n");
      exit(1);
   }
   printf("Connected: server's address is %s\n", hp->h_name);
   printf("Transmit:\n");
   gets(sbuf);
   write(sd, sbuf, BUFLEN);
   printf("Receive:\n");
   bp = rbuf;
   bytes_to_read = BUFLEN;
   while ((n = read(sd, bp, bytes_to_read)) > 0)
   {
      bp += n;
      bytes_to_read -= n;
   }
   printf("%s\n", rbuf);
   close(sd);
   return (0);
}