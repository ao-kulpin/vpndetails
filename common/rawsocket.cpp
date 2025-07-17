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
if(iph->proto == IPPROTO_ICMP)
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

void RawTcpSocket::close() {
    if (mSockFd != SOCKET_ERROR) {
        closesocket(mSockFd);
        mSockFd = SOCKET_ERROR;
    }
}



