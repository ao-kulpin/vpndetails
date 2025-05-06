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
#define DNS_SERVER "1.1.1.1"   // Cloudflare
//#define DNS_SERVER "192.168.0.1"
//#define DNS_SERVER "109.195.80.1"
//#define DNS_SERVER "0.0.0.0"
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

    dnsHeader->id = (unsigned short) htons(getpid() & 0xFFFF); // Уникальный идентификатор запроса
    dnsHeader->rd = 1;                                       // Рекурсивный запрос включен

    dnsHeader->qcount = htons(1);                          // Один вопрос
    dnsHeader->opcode = 0;

    ///// unsigned
        char* qname = buffer + sizeof(DNSHeader);

    // Форматирование имени хоста в соответствии с форматом DNS (с длиной каждого сегмента)
    const char* token = strtok(hostname, ".");

    while (token != NULL) {
        *qname++ = (unsigned char)strlen(token);
        strcpy((char*)qname, token);
        qname += strlen(token);
        token = strtok(NULL, ".");
    }

    *qname++ = 0;                                            // Завершение имени нулевым байтом

    *((unsigned short*)qname) = htons(1);                   // Тип A (IPv4)
    *((unsigned short*)(qname + 2)) = htons(1);             // Класс IN (Internet)

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

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

    SOCKET sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (sockfd == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Указание IP-адреса интерфейса
    struct in_addr iface_addr;
    inet_pton(AF_INET, "192.168.0.102", &iface_addr); // Замените на ваш IP-адрес интерфейса
    DWORD index = 0;
#if 0
    if (setsockopt(sockfd, IPPROTO_IP, IP_UNICAST_IF,
                   (const char*) &iface_addr, sizeof iface_addr)){
        printf("setsockopt fails %d\n", WSAGetLastError());
        return 1;
    }
#endif

    struct sockaddr_in dest;

    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);

    if (inet_pton(AF_INET, DNS_SERVER, &dest.sin_addr) <= 0) {
        printf("Invalid address/ Address not supported\n");
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    ///// unsigned
        char buffer[512];

    size_t queryLength;

    CreateDnsQuery(hostname, buffer, &queryLength);


    if (sendto(sockfd, buffer, queryLength, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        printf("Sendto failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    struct sockaddr_in addr;
    // addr.sin_family = AF_INET;
    //addr.sin_addr.s_addr = INADDR_ANY; // Принимаем соединения на всех интерфейсах
    //addr.sin_port = htons(12345); // Привязываем к порту 12345

    int addr_len = sizeof(addr);
    if (getsockname(sockfd, (struct sockaddr*)&addr, &addr_len)
        == SOCKET_ERROR) {
        printf("getsockname() failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        WSACleanup();
        return 1;
    }

    printf("Socket is bound to port: %d\n", ntohs(addr.sin_port));


    struct sockaddr_in from;

    int fromlen = sizeof(from);
    printf("waiting an answer from %s ...\n", DNS_SERVER);
   int recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&from, &fromlen);

   if (recv_len < 0) {
       printf("Recvfrom failed: %d\n", WSAGetLastError());
       closesocket(sockfd);
       WSACleanup();
       return 1;
   }


   DNSHeader* responseHeader = (DNSHeader*)buffer;
   printf("Received response: %d\n", responseHeader->rcode);
   printf("Authority: %d\n", responseHeader->aa);
   printf("Recursion: %d\n", responseHeader->ra);

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
           answerPtr += sizeof(unsigned short)*4 + 2 + sizeof(struct in_addr);
       }
   } else {
       printf("No answers received.\n");
   }

   closesocket(sockfd);
   WSACleanup();

   a.exit();
   return 0;
}

