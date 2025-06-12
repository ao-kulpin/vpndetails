#ifndef SERVERDATA_H
#define SERVERDATA_H

#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#endif // _WIN32

#include <QHostAddress>
#include <QMutex>
#include <QWaitCondition>

#include <atomic>
#include <map>
#include <queue>
#include <memory>

#include "protocol.h"
#include "vpntypes.h"

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

class ClientRequestKey {
public:
    IPAddr      destIp = 0;
    u_short     proto = 0;
};

bool operator < (const ClientRequestKey& lhs, const ClientRequestKey& rhs);

class ClientRequestInfo {
public:
    u_int       clientId = 0;
    u_int       answerCount = 0;
    u_int64     serverTime = 0,
                clientTime = 0;
};

using ClientRequestVector = std::vector<ClientRequestInfo>;

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
    std::atomic<u_int64>        serverTimer {0};
    u_short                     serverPort {55555};
///    QHostAddress                realAdapterIP {"192.168.0.104"};
    QHostAddress                realAdapterIP {"192.168.8.100"};
    bool                        haveQuit {false};

    std::map<PortKey, PortInfo> clientPortMap;
    std::map<u_short, PortInfo> serverPortMap;
    std::map<u_int, ClientSocket*> socketMap; // clientId -> clientSocket

    std::map<ClientRequestKey, std::unique_ptr<ClientRequestVector>> requestMap;

    using QueueElemType = std::unique_ptr<IPPacket>;
    std::queue<QueueElemType>   clientReceiveQueue;
    QMutex                      clientReceiveMutex;
    QWaitCondition              clientReceiveWC;

    PortProvider                portProvider;

#ifdef __linux__

    qint64                      arpTime {2000}; // ms

#endif //  __linux__

};

extern ServerData sdata;

#endif // SERVERDATA_H
