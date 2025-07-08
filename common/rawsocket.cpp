#include "rawsocket.h"

RawTcpSocket::RawTcpSocket(IP4Addr _realAdaptIP) {
////////    mSockFd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    mSockFd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);

    if (mSockFd == INVALID_SOCKET) {
        mError = WSAGetLastError();
        return;
    }

#if 0
    sockaddr_in boundAddr;
    int boundLen = 0;
    if (getsockname(mSockFd, (sockaddr*)&boundAddr, &boundLen) == SOCKET_ERROR) {
        printf("+++ getsockname() fails: %d\n", WSAGetLastError());
        return;
    }
#endif

    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof localAddr);
    localAddr.sin_family        = AF_INET;
    localAddr.sin_addr.s_addr   = htonl(_realAdaptIP);
////    localAddr.sin_addr.s_addr = inet_addr("192.168.0.103");
    localAddr.sin_port = 0;

    if (bind(mSockFd, (sockaddr*) &localAddr, sizeof localAddr) == SOCKET_ERROR) {
        printf("+++ raw tcp bind: %08X/%08lX %d\n", _realAdaptIP, localAddr.sin_addr.s_addr, WSAGetLastError());
        mError =  WSAGetLastError();
        closesocket(mSockFd);
        mSockFd = INVALID_SOCKET;
        return;
    }

    mError = 0;
}

bool RawTcpSocket::send(const IPPacket& _packet) {
    const auto* iph = _packet.header();

    assert(iph->proto == IPPROTO_TCP && isOK());

    const auto* tch = _packet.tcpHeader();

    sockaddr_in sdest;
    memset(&sdest, 0, sizeof sdest);
    sdest.sin_family = AF_INET;
    sdest.sin_addr.s_addr = iph->destAddr;
    sdest.sin_port = tch->dport;

    auto res = sendto(mSockFd, (const char*) _packet.data(), _packet.size(),
           0, (sockaddr*) &sdest, sizeof sdest);

    if (res == SOCKET_ERROR) {
        mError = 2;
        return false;
    }
    else
        return true;
}

void RawTcpSocket::close() {
    if (mSockFd != SOCKET_ERROR) {
        closesocket(mSockFd);
        mSockFd = SOCKET_ERROR;
    }
}



