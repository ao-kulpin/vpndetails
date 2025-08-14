#ifndef DUMMYSOCKET_H
#define DUMMYSOCKET_H

#include "vpntypes.h"
#include "protocol.h"

#include "pcap.h"

class DummySocket
{
public:
    DummySocket(IP4Addr _Ip, unsigned _port);
    ~DummySocket();

    bool isOK()                         { return mError == 0; }
    int  getError()                     { return mError; }

private:
    IP4Addr     mIp = -1;
    unsigned    mPort = - 1;
    int         mError  = -1;
    SOCKET      mSockFd = SOCKET_ERROR;
};

#endif // DUMMYSOCKET_H
