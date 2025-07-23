#ifndef RAWSOCKET_H
#define RAWSOCKET_H

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "vpntypes.h"
#include "protocol.h"

#include "pcap.h"

class RawTcpSocket {
public:

    RawTcpSocket(IP4Addr _realAdaptIP);
    ~RawTcpSocket()                     { close(); }

    bool isOK()                         { return mError == 0; }
    int  getError()                     { return mError; }
    IP4Addr getBoundIp();

    bool send(const IPPacket& _packet);
    int  receive(char *buf, int len);
    void close();

private:
    int         mError  = -1;
    SOCKET      mSockFd = INVALID_SOCKET;
};

#endif // RAWSOCKET_H
