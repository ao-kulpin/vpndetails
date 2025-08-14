#ifndef RAWSOCKET_H
#define RAWSOCKET_H

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
    SOCKET      mSockFd = SOCKET_ERROR;
};

#endif // RAWSOCKET_H
