#ifndef CLIENTDATA_H
#define CLIENTDATA_H

#include <memory>
#include <queue>


#include <winsock2.h>  // Сначала подключаем winsock2.h
#include <windows.h>   // Затем подключаем windows.h

#include <QHostAddress>
#include <QMutex>
#include <QWaitCondition>

#include "wintunlib.h"
#include "ProtoBuilder.h"

class VPNSocket;

class ClientData {
public:
    VPNSocket*   vpnSocket      {nullptr};
    WINTUN_ADAPTER_HANDLE
                 virtAdapter    {nullptr};
    const GUID   adapGuid       { 0xdeadc001, 0xbeef, 0xbabe, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    WINTUN_SESSION_HANDLE
                 session        {nullptr};
    int          ringSize       {0x400000};
    int          defaultMetricAdd {100};

    QHostAddress serverIP       {"127.0.0.1"};
    ///QHostAddress serverIP       {"194.87.138.48"};
    u_short      serverPort     { 55555 };
    u_int        connectTime    { 2000 };
    u_int        clientId       { 0 };
    QHostAddress virtAdapterIP  {"10.6.7.7"};
    ///    QHostAddress realAdapterIP  {"192.168.0.104"};
    QHostAddress realAdapterIP  {"192.168.8.101"};
    /// QHostAddress realAdapterIP  {"127.0.0.1"};
///    QHostAddress                realAdapterIP {"194.87.138.48"};

    int          virtAdapterMaskLen {24};

    HANDLE       quitEvent      {0};
    bool         haveQuit       {false};

    using QueueElemType =       std::unique_ptr<IPPacket>;
    std::queue<QueueElemType>   virtReceiveQueue;
    QMutex                      virtReceiveMutex;

    std::queue<QueueElemType>   serverReceiveQueue;
    QMutex                      serverReceiveMutex;
    QWaitCondition              serverReceiveWC;
};

extern ClientData cdata;


#endif // CLIENTDATA_H
