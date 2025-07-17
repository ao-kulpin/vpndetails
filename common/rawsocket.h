#ifndef RAWSOCKET_H
#define RAWSOCKET_H

#include <winsock2.h>

#include "vpntypes.h"
#include "protocol.h"

class RawTcpSocket {
public:

    RawTcpSocket(IP4Addr _realAdaptIP);
    ~RawTcpSocket()                     { close(); }

    bool isOK()                         { return mError == 0; }
    int  getError()                     { return mError; }
    IP4Addr getBoundIp();

    bool send(const IPPacket& _packet);
    void close();

private:
    int     mError  = -1;
    SOCKET  mSockFd = INVALID_SOCKET;
};

#endif // RAWSOCKET_H
