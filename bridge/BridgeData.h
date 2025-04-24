#ifndef BRIDGEDATA_H
#define BRIDGEDATA_H

//#include <winsock2.h>  // Сначала подключаем winsock2.h
//#include <windows.h>   // Затем подключаем windows.h

#include <QHostAddress>

#include <queue>
#include <memory>

#include "wintunlib.h"
#include "protocol.h"

class BridgeData {
public:
    WINTUN_ADAPTER_HANDLE virtAdapter   {nullptr};
    const GUID adapGuid                 // {0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }};
                                        { 0xdeadc001, 0xbeef, 0xbabe, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };
    QHostAddress virtAdapterIP          {"10.6.7.7"};
    QHostAddress realAdapterIP          {"192.168.0.102"};
    int virtAdapterMaskLen              {24};
    WINTUN_SESSION_HANDLE session       {nullptr};
    int ringSize                        {0x400000};
    int defaultMetricAdd                {100};

    HANDLE quitEvent                    {0};
    bool haveQuit                       {false};

    using QueueElemType =              std::unique_ptr<IPPacket>;
    std::queue<QueueElemType>          virtReceiveQueue;
};

extern BridgeData bdata;

#endif // BRIDGEDATA_H
