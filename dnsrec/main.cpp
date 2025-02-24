#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <QCoreApplication>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

//#define DNS_SERVER "8.8.8.8" // Google Public DNS
#define DNS_SERVER "192.168.0.1" // Google Public DNS
#define DNS_PORT 53

// Структура для DNS-запроса
typedef struct {
    unsigned short id;       // Идентификатор запроса
    unsigned char rd : 1;   // Рекурсивный запрос
    unsigned char tc : 1;   // Ответ слишком большой
    unsigned char aa : 1;   // Авторитетный ответ
    unsigned char opcode : 4; // Код операции
    unsigned char qr : 1;     // Запрос или ответ
    unsigned char rcode : 4;  // Код ответа
    unsigned char z : 3;      // Зарезервировано
    unsigned char ra : 1;     // Рекурсивные возможности
    unsigned short qcount;     // Количество вопросов
    unsigned short ancount;    // Количество ответов
    unsigned short nscount;    // Количество записей в авторитете
    unsigned short arcount;    // Количество записей в дополнительных данных
} DNSHeader;

// Функция для создания DNS-запроса
void CreateDnsQuery(char* hostname, char* buffer, size_t* queryLength) {
    DNSHeader* dnsHeader = (DNSHeader*)buffer;
    memset (dnsHeader, 0, sizeof *dnsHeader);
    printf("CreateDnsQuery() 1\n");

    dnsHeader->id = (unsigned short) htons(getpid() & 0xFFFF); // Уникальный идентификатор запроса
    dnsHeader->rd = 1;                                       // Рекурсивный запрос включен
    printf("CreateDnsQuery() 1.1\n");

    dnsHeader->qcount = htons(1);                          // Один вопрос
    dnsHeader->opcode = 0;
    printf("CreateDnsQuery() 1.2\n");

    ///// unsigned
        char* qname = buffer + sizeof(DNSHeader);

    printf("CreateDnsQuery() 1.2.1 %s\n", hostname);

    // Форматирование имени хоста в соответствии с форматом DNS (с длиной каждого сегмента)
    const char* token = strtok(hostname, ".");
    printf("CreateDnsQuery() 1.2.2\n");

    while (token != NULL) {
        printf("tok: %s\n", token);
        *qname++ = (unsigned char)strlen(token);
        strcpy((char*)qname, token);
        qname += strlen(token);
        token = strtok(NULL, ".");
    }
    printf("CreateDnsQuery() 1.3\n");


    *qname++ = 0;                                            // Завершение имени нулевым байтом

    printf("CreateDnsQuery() 2\n");

    *((unsigned short*)qname) = htons(1);                   // Тип A (IPv4)
    *((unsigned short*)(qname + 2)) = htons(1);             // Класс IN (Internet)
    printf("CreateDnsQuery() 3\n");

    *queryLength = qname - buffer + 4;                     // Длина запроса (заголовок + вопрос)
}

inline
static
    const char* skipName(const char* ptr) {
    auto len = *(const unsigned char*) ptr;
    if ((len & 0xC0) == 0xC0)
        // label compression
        return ptr + 2;
    else {
        return ptr + len + 1;
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    char hostname[1024] = "akulpin2.ru";               // Замените на нужное имя хоста
    if (argc > 1)
        strcpy(hostname, argv[1]);

    printf("host: %s\n", hostname);

    WSADATA wsaData;
    printf("main() 1\n");

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    printf("socket %p\n", sockfd);

    printf("main() 1.1\n");


    if (sockfd == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);

    if (inet_pton(AF_INET, DNS_SERVER, &dest.sin_addr) <= 0) {
        printf("Invalid address/ Address not supported\n");
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }
    printf("main() 1.2\n");

    ///// unsigned
        char buffer[512];

    size_t queryLength;

    CreateDnsQuery(hostname, buffer, &queryLength);
    printf("main() 2\n");


    if (sendto(sockfd, buffer, queryLength, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        printf("Sendto failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    printf("main() 3\n");

    struct sockaddr_in from;

    int fromlen = sizeof(from);

   int recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromlen);

    printf("main() 4 len %d\n", recv_len);

   if (recv_len < 0) {
       printf("Recvfrom failed: %d\n", WSAGetLastError());
       closesocket(sockfd);
       WSACleanup();
       return 1;
   }


   DNSHeader* responseHeader = (DNSHeader*)buffer;
   printf("Received response %d:\n", responseHeader->rcode);

   if(ntohs(responseHeader->ancount) > 0) {

        ///// unsigned
        const char* answerPtr = buffer + sizeof(DNSHeader);

       while (*answerPtr != 0) {
           answerPtr = skipName(answerPtr);
       }

       answerPtr += 1 + sizeof(unsigned short) * 2;


       for(int i=0; i<ntohs(responseHeader->ancount); i++) {
           while (*answerPtr != 0) {
               answerPtr = skipName(answerPtr);
           }
           struct in_addr ipAddr;
/////           memcpy(&ipAddr.s_addr, answerPtr + sizeof(unsigned short)*3 + i * sizeof(struct in_addr), sizeof(struct in_addr));
           memcpy(&ipAddr.s_addr, answerPtr + sizeof(unsigned short)*4 + 2, sizeof(struct in_addr));
           printf("IP Address: %s\n", inet_ntoa(ipAddr));
           answerPtr += sizeof(unsigned short)*3 + sizeof(struct in_addr);
       }
   } else {
       printf("No answers received.\n");
   }

   closesocket(sockfd);
   WSACleanup();

   a.exit();
   return 0;
}

