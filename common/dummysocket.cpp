#include "dummysocket.h"

#ifdef __linux__
#include <unistd.h>
#endif

static
int getLastError() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static
    void closeSocket(SOCKET _sock) {
#ifdef _WIN32
    closesocket(_sock);
#else
    close(_sock);
#endif
}


DummySocket::DummySocket(IP4Addr _Ip, unsigned _port)
    : mIp(_Ip), mPort(_port)
{
    mSockFd = socket(AF_INET, SOCK_STREAM, 0);

    if (mSockFd == SOCKET_ERROR) {
        mError = getLastError();
        return;
    }

    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof localAddr);
    localAddr.sin_family        = AF_INET;
    localAddr.sin_addr.s_addr   = htonl(mIp);
    localAddr.sin_port          = htons(mPort);

    if (bind(mSockFd, (sockaddr*) &localAddr, sizeof localAddr) == SOCKET_ERROR) {
        mError =  getLastError();
        printf("+++ dummy socket bind: %08X/%08X %d\n", mIp, localAddr.sin_addr.s_addr, getError());
        closeSocket(mSockFd);
        mSockFd = SOCKET_ERROR;
        return;
    }

    if (listen(mSockFd, 10) == SOCKET_ERROR) {
        mError = getLastError();
        closeSocket(mSockFd);
        mSockFd = SOCKET_ERROR;
        return;
    }

    mError = 0;
}

DummySocket::~DummySocket() {

}
