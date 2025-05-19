#ifndef CLIENTDATA_H
#define CLIENTDATA_H

#include <winsock2.h>  // Сначала подключаем winsock2.h
#include <windows.h>   // Затем подключаем windows.h

#include <QHostAddress>


class ClientData {
public:
    QHostAddress serverIP       {"127.0.0.1"};
    u_short      serverPort     { 55555 };
    u_int        connectTime    { 2000 };
    u_int        clientId       { 0 };
};

extern ClientData cdata;


#endif // CLIENTDATA_H
