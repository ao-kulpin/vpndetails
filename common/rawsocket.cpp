#include <winsock2.h>
//#include <windows.h>
//#include <iphlpapi.h>
#include <ws2tcpip.h>


#include <QHostAddress>
#include "rawsocket.h"

RawTcpSocket::RawTcpSocket(IP4Addr _realAdaptIP) {
    mSockFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
////////    mSockFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
//////    mSockFd =  WSASocket(AF_INET, SOCK_RAW, IPPROTO_IP, NULL, 0, 0);

    if (mSockFd == INVALID_SOCKET) {
        mError = WSAGetLastError();
        return;
    }

//#if 0
    int optval = 1;
    if (setsockopt(mSockFd, IPPROTO_IP, IP_HDRINCL,
                   (char*) &optval, sizeof(optval)) == SOCKET_ERROR) {
        mError = WSAGetLastError();
        return;
    }
// #endif

    const int RawSockTimeout = 4000;
    int timeout = RawSockTimeout;
    //timeout.tv_sec = RawSockTimeout / 1000;
    //timeout.tv_usec = RawSockTimeout % 1000;

    if (setsockopt(mSockFd, SOL_SOCKET, SO_RCVTIMEO, (char*) &timeout, sizeof(timeout))
        == SOCKET_ERROR) {
        printf("+++ setsockopt(SO_RCVTIMEO) failed\n");
        mError = WSAGetLastError();
        return;
    }

    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof localAddr);
    localAddr.sin_family        = AF_INET;
    localAddr.sin_addr.s_addr   = htonl(_realAdaptIP);
////    localAddr.sin_addr.s_addr = inet_addr("192.168.0.103");
    localAddr.sin_port = 0; /////

//#if 0
    if (bind(mSockFd, (sockaddr*) &localAddr, sizeof localAddr) == SOCKET_ERROR) {
        printf("+++ raw tcp bind: %08X/%08lX %d\n", _realAdaptIP, localAddr.sin_addr.s_addr, WSAGetLastError());
        mError =  WSAGetLastError();
        closesocket(mSockFd);
        mSockFd = INVALID_SOCKET;
        return;
    }
//#endif

    DWORD flag = RCVALL_ON;
    DWORD dwBytesRet = 0;
    if (WSAIoctl(mSockFd, SIO_RCVALL, &flag, sizeof(flag), NULL, 0,
                 &dwBytesRet, NULL, NULL) == SOCKET_ERROR) {
        printf("WSAIoctl(SIO_RCVALL) failed: %d\n", WSAGetLastError());
        mError = WSAGetLastError();
        return;
    }


    mError = 0;
}

IP4Addr RawTcpSocket::getBoundIp() {
    assert(isOK());

    sockaddr_in local_addr;
    int addr_len = sizeof local_addr;
    if (getsockname(mSockFd, (sockaddr*) &local_addr, &addr_len) < 0)
        return 0;
    else
        return ntohl(local_addr.sin_addr.S_un.S_addr);
}

bool RawTcpSocket::send(const IPPacket& _packet) {
    const auto* iph = _packet.header();

////////    assert(iph->proto == IPPROTO_TCP && isOK());

    const auto* tch = _packet.tcpHeader();

    sockaddr_in sdest;
    memset(&sdest, 0, sizeof sdest);
    sdest.sin_family = AF_INET;
    sdest.sin_addr.s_addr = iph->destAddr;
if(iph->proto != IPPROTO_ICMP)
    sdest.sin_port = tch->dport;

    auto res = sendto(mSockFd, (const char*) _packet.data(), _packet.size(),
           0, (sockaddr*) &sdest, sizeof sdest);

    if (res == SOCKET_ERROR) {
        printf("+++ RawTcpSocket::send() failed\n");
        mError = 2;
        return false;
    }
    else {
        printf("+++ RawTcpSocket::send() succeed %d/%d\n", res, _packet.size());
        printf("+++ RawTcpSocket is bound to %s\n",
               QHostAddress(getBoundIp()).toString().toStdString().c_str());
        printf("+++ proto %d checksum %04X\n", iph->proto, ntohs(iph->checksum));
        printf("+++ src %s dst %s\n",
                QHostAddress(ntohl(iph->srcAddr)).toString().toStdString().c_str(),
                QHostAddress(ntohl(iph->destAddr)).toString().toStdString().c_str());

        return true;
    }
}

int RawTcpSocket::receive(char *buf, int len) {
    assert (isOK());
    auto res = recv(mSockFd, buf, len, 0);

    if (res < 0) {
        auto wse = WSAGetLastError();
        if (wse != WSAETIMEDOUT)
            mError = wse;
    }

    return res;
}

void RawTcpSocket::close() {
    if (mSockFd != SOCKET_ERROR) {
        closesocket(mSockFd);
        mSockFd = SOCKET_ERROR;
    }
}



