#ifndef SERVERDATA_H
#define SERVERDATA_H

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <QHostAddress>
#include <QMutex>
#include <QWaitCondition>

#include <atomic>
#include <map>
#include <queue>
#include <memory>

#include "protocol.h"

struct PortKey {
    u_int       clientId;
    IPAddr      clientIp;
    u_short     clientPort;
};

bool operator < (const PortKey& lhs, const PortKey& rhs);

struct PortInfo {
    u_int       clientId;
    IPAddr      clientIp;
    u_short     clientPort;
    u_short     serverPort;
};

class PortProvider {
public:
    static const int PortMin = 49152, PortMax = 0xFFFF;
    u_short get();

private:
    u_int   mPort = PortMin;
};

class ClientSocket;

class ServerData {
public:
    std::atomic<u_int>          clientCount {0};
    u_short                     serverPort {55555};
    QHostAddress                realAdapterIP {"192.168.0.103"};
    bool                        haveQuit {false};

    std::map<PortKey, PortInfo> clientPortMap;
    std::map<u_short, PortInfo> serverPortMap;
    std::map<u_int, ClientSocket*> socketMap; // clientId -> clientSocket

    using QueueElemType = std::unique_ptr<IPPacket>;
    std::queue<QueueElemType>   clientReceiveQueue;
    QMutex                      clientReceiveMutex;
    QWaitCondition              clientReceiveWC;

    PortProvider                portProvider;
};

extern ServerData sdata;

#endif // SERVERDATA_H
