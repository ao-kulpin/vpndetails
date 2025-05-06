#include <winsock2.h>
#include <ws2tcpip.h>

#include <csignal>

#include <QCoreApplication>

#include <stdio.h>

#pragma comment(lib, "Ws2_32.lib")

#include <QCoreApplication>

SOCKET sock;

void signalHandler(int signum) {
    printf("\nTerminated by user\n");
    closesocket(sock); // Закрываем сокет
    QCoreApplication::quit();
}


int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }

/////    sock = socket(AF_INET, SOCK_STREAM, 0);
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        printf("Can't create socket: %d\n", WSAGetLastError());
        return 1;
    }

    // Устанавливаем параметр для автоматического назначения порта
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0; // Автоматически выделить порт

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("Can't bind socket: %d\n",  WSAGetLastError());
        closesocket(sock);
        return 1;
    }

    // Получаем номер порта
    int len = sizeof(addr);
    if (getsockname(sock, (sockaddr*)&addr, &len) == SOCKET_ERROR) {
        printf("getsockname() fails: %\n", WSAGetLastError());
        closesocket(sock);
        return -1;
    }

    int port = ntohs(addr.sin_port); // Преобразуем порт в сетевой порядок байт
    /////closesocket(sock); // Закрываем сокет

    printf("Port: %d\n", port);
    printf("\nWaiting for Ctrl-C ...\n\n");

    std::signal(SIGINT, signalHandler);

    return a.exec();

}
