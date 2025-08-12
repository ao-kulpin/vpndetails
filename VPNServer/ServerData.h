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
#include "rawsocket.h"

struct PortKey {
    u_int       clientId;
    IP4Addr     clientIp;
    u_short     clientPort;
};

bool operator < (const PortKey& lhs, const PortKey& rhs);

struct PortInfo {
    u_int       clientId;
    IP4Addr     clientIp;
    u_short     clientPort;
    u_short     serverPort;
    SOCKET      sock;
};

class ClientRequestKey {
public:
    IP4Addr     destIp = 0;
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
    u_short get(PortInfo& _pi);

private:
    u_int   mPort = PortMin;
};

class ClientSocket;

class ServerData {
public:
    std::atomic<u_int>          clientCount {0};
    std::atomic<u_int64>        serverTimer {0};
    u_short                     serverPort {55555};
 ///   QHostAddress                realAdapterIP {"192.168.0.101"};
//    QHostAddress                realAdapterIP {"192.168.8.100"};
    QHostAddress                realAdapterIP {"194.87.138.48"};
    bool                        haveQuit {false};
    unsigned                    ringBufSize {200 * 1024};

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

    qint64                      arpTime {5000}; //{2000}; // ms

#endif //  __linux__

    std::unique_ptr<RawTcpSocket> tcpSocket;

};

extern ServerData sdata;

#endif // SERVERDATA_H
