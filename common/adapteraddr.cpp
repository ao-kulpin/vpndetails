#include <stdio.h>
#include <string.h>
#include "adapteraddr.h"
#include "killer.h"
#include "protocol.h"

#ifdef __linux__

#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>

#include <QDateTime>
#include <QFile>
#include <QTextStream>

#endif // __linux__

#ifdef _WIN32

bool AdapterAddr::getMacAddress(IP4Addr destIp, u_char macAddress[]) {
    IP4Addr netDestIp = htonl(destIp);
    memset(macAddress, 0, 6);
    for (auto* adapt = getAdapts(); adapt; adapt = adapt->Next) {
/////        printf("+++ adapt Name: %s\n", adapt->AdapterName);
        for (auto* unic = adapt->FirstUnicastAddress; unic; unic = unic->Next) {
            ULONG ip4 = ((sockaddr_in*) unic->Address.lpSockaddr)->sin_addr.S_un.S_addr;
/////            printf("+++ getMac ip: %08X macLen: %ld\n", ip4, adapt->PhysicalAddressLength);
            if (unic->Address.lpSockaddr->sa_family == AF_INET && netDestIp == ip4) {

                if (adapt->PhysicalAddressLength !=6)
                    return false;

                memcpy(macAddress, adapt->PhysicalAddress, 6);
                return true;
            }
        }
    }
    return false;
}

bool AdapterAddr::getGatewayMacAddress(IP4Addr _srcIp,
                                       IP4Addr _destIp, u_char _macAddress[]) {
    ULONG macAddr[2] = { 0 };
    ULONG phyAddrLen = 6;  /* default to length of six bytes */

    //Send an arp packet
    if (SendARP(htonl(_destIp), 0, macAddr, &phyAddrLen) != NO_ERROR || phyAddrLen != 6)
        return false;

    memcpy(_macAddress, macAddr, 6);
    return true;
}

bool AdapterAddr::getGatewayIP(IP4Addr adaptIp, IP4Addr *gatewayIP) {
    const IP4Addr netAdaptIp = htonl(adaptIp);

    *gatewayIP = 0;

    for (auto* adapt = getAdapts(); adapt; adapt = adapt->Next) {
        for (auto*  unic = adapt->FirstUnicastAddress; unic; unic = unic->Next) {
            IP4Addr ip4 = ((sockaddr_in*) unic->Address.lpSockaddr)->sin_addr.S_un.S_addr;
            printf("+++ ip4: %08X\n", ntohl(ip4));

            if (unic->Address.lpSockaddr->sa_family == AF_INET && netAdaptIp == ip4 && adapt->FirstGatewayAddress) {
                *gatewayIP = ntohl(
                    ((sockaddr_in*) adapt->FirstGatewayAddress->Address.lpSockaddr)->sin_addr.S_un.S_addr);
                return true;
            }
        }
    }
    return false;
}

IP_ADAPTER_ADDRESSES* AdapterAddr::getAdapts() {
    if (!mAdaptList) {
      ULONG outBufLen = 0;
        int rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, 0, &outBufLen);
        if (rc != ERROR_BUFFER_OVERFLOW && rc != NO_ERROR
                                                || !outBufLen) {
//////          printf("+++ GetAdaptersAddresses fails 1 rc: %d\n", rc);
          return nullptr;
        }

      mAdaptList.reset(reinterpret_cast<IP_ADAPTER_ADDRESSES*> (new u_char[outBufLen]));
      if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS,
                               NULL, mAdaptList.get(), &outBufLen) != NO_ERROR) {
//////////          printf("+++ GetAdaptersAddresses fails 2\n");
          mAdaptList.reset(nullptr);
          return nullptr;
      }
    }
    return mAdaptList.get();
}

#endif // _WIN32

#ifdef __linux__

static
bool checkFamily(int _family) {
    return _family == AF_PACKET || _family == PF_INET;
}

bool AdapterAddr::getMacAddress(IP4Addr destIP, u_char macAddress[]) {
    memset(macAddress, 0, 6);

    ifreq req;
    memset(&req, 0, sizeof req);
    if (!getAdaptName(destIP, req.ifr_name))
        return false;

    printf("+++ getMacAddress 1 %s\n", req.ifr_name);

     int sockFd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sockFd < 0)
         return false;
    Killer sfk ([&]{ close(sockFd); });

    if (ioctl(sockFd, SIOCGIFHWADDR, &req) < 0)
        return false;

    memcpy(macAddress, req.ifr_hwaddr.sa_data, 6);
    return true;

#if 0

    for (auto* adapt = getAdapts(); adapt; adapt = adapt->ifa_next) {
printf("+++ ip %08X %08X fam %d\n", ((sockaddr_in*) adapt->ifa_addr)->sin_addr.s_addr,
        destIP, adapt->ifa_addr->sa_family);
        if (adapt->ifa_addr && checkFamily(adapt->ifa_addr->sa_family)      // Ethernet
            && ((sockaddr_in*) adapt->ifa_addr)->sin_addr.s_addr == destIP) {
            auto* sdl = (sockaddr_dl*) adapt->ifa_addr;
            memcpy(macAddress, adapt->ifa_addr->sa_data, 6);
            return true;
        }
    }
    return false;
#endif
}

bool AdapterAddr::getGatewayIP(IP4Addr adaptIp, IP4Addr *gatewayIP) {
    *gatewayIP = 0;

    char adaptName[IFNAMSIZ];
    if (!getAdaptName(adaptIp, adaptName))
        return false;

    QFile routeFile("/proc/net/route");  // size is 0 !!!

    if (!routeFile.open(QIODevice::ReadOnly | QIODevice::Text))
        return false;

    Killer rfk ([&] { routeFile.close(); });

    QTextStream routeStream(&routeFile);

    for(auto line = routeStream.readLine(); !line.isNull(); line = routeStream.readLine()) {
        QTextStream lineStream(&line);
        QString iFace, destination, gateway;
        u_long flags;
        lineStream >> iFace >> destination >> gateway >> flags;

///        printf("+++ Gateway %s %s %s\n", iFace.toStdString().c_str(),
///               destination.toStdString().c_str(),
///               gateway.toStdString().c_str());

        if (iFace == adaptName
            && destination == "00000000"
            && gateway != "00000000") {

            *gatewayIP = ntohl(strtoul(gateway.toStdString().c_str(), 0, 16));
            return true;
        }
    }
    return false;
}

bool AdapterAddr::getGatewayMacAddress(IP4Addr _srcIp, IP4Addr _destIp, u_char _macAddress[]) {
    ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    if (!getAdaptName(_srcIp, ifr.ifr_name))
        return false;

printf("+++ getGatewayMacAddress 2 in=%s src %08X dest %08X\n", ifr.ifr_name, _srcIp, _destIp);

    const IP4Addr netSrcIp  = htonl(_srcIp);
    const IP4Addr netDestIp = htonl(_destIp);

    int sockFd = socket(AF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    if (sockFd == -1)
        return false;

    Killer sfk ([&] { close(sockFd); });

    struct timeval timeout;
///    timeout.tv_sec = sdata.arpTime / 1000;
///    timeout.tv_usec = sdata.arpTime % 1000;
    const int ArpTime = 5000;
    timeout.tv_sec = ArpTime / 1000;
    timeout.tv_usec = ArpTime % 1000;

    if (setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        return false;

    if (ioctl(sockFd, SIOCGIFHWADDR, &ifr) < 0)
        return false;

auto& sd = ifr.ifr_hwaddr.sa_data;
printf("+++ getGatewayMacAddress mac: %02X %02X %02X %02X %02X %02X\n",
       u_char(sd[0]), u_char(sd[1]), u_char(sd[2]), u_char(sd[3]), u_char(sd[4]), u_char(sd[5]));

    ether_arp arp_req;
    memset(&arp_req, 0, sizeof(arp_req));

    arp_req.ea_hdr.ar_hrd = htons(1);
    arp_req.ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_req.ea_hdr.ar_hln = ETH_ALEN;
    arp_req.ea_hdr.ar_pln = 4;

    arp_req.arp_op = htons(ARPOP_REQUEST);
    memcpy(arp_req.arp_sha, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

    *(IP4Addr*) &arp_req.arp_spa = netSrcIp;
    *(IP4Addr*) &arp_req.arp_tpa = netDestIp;

    const u_int BufSize = sizeof(EthernetHeader) + sizeof(ether_arp);
    u_char reqBuf[BufSize];
    auto* eth = (EthernetHeader*) reqBuf;
    auto* arp = (ether_arp*) (reqBuf + sizeof(EthernetHeader));

    memset(&reqBuf, 0, sizeof reqBuf);
    memcpy(eth->srcMac, arp_req.arp_sha, ETH_ALEN);
    memset(eth->destMac, 0xFF, ETH_ALEN);       // broadcast
    eth->type = htons(ETH_P_ARP);

    memcpy(arp, &arp_req, sizeof arp_req);

    sockaddr_ll sendAddr;
    memset(&sendAddr, 0, sizeof sendAddr);
    sendAddr.sll_ifindex = if_nametoindex(ifr.ifr_name);

    printf("+++ getGatewayMacAddress sll_ifindex=%d\n", sendAddr.sll_ifindex);

    sendAddr.sll_family   = AF_PACKET;
    sendAddr.sll_protocol = htons(ETH_P_ARP);
    sendAddr.sll_halen = ETH_ALEN;
    memcpy(sendAddr.sll_addr, arp_req.arp_sha, ETH_ALEN);

    // Send ARP request

    if (sendto(sockFd, reqBuf, BufSize, 0, (sockaddr*) &sendAddr, sizeof(sendAddr)) == -1)
        return false;

    // Receive ARP reply

    u_char replyBuf[2048];
    auto replyStart = QDateTime::currentMSecsSinceEpoch();

    while (true) {
        auto received = recv(sockFd, replyBuf, sizeof replyBuf, 0);
 printf("+++ getGatewayMacAddress() received=%ld\n", received);
        if (received < 0)
            return false;

        auto* eh = (ether_header*) replyBuf;
        auto* ea = (ether_arp*) (replyBuf + sizeof(ether_header));
printf("+++ getGatewayMacAddress() type=%04X\n", ntohs(eh->ether_type));

        if (ntohs(eh->ether_type) == ETHERTYPE_ARP
            && ntohs(ea->arp_op) == ARPOP_REPLY
            && *(IP4Addr*) &ea->arp_spa == netDestIp
            && *(IP4Addr*) &ea->arp_tpa == netSrcIp) {
            // ARP replay

            memcpy(_macAddress, ea->arp_sha, ETH_ALEN);
 printf("+++ Arp reply: source: %08X target: %08X\n",
                   ntohl(*(IP4Addr*) &ea->arp_spa), ntohl(*(IP4Addr*) &ea->arp_tpa));
            return true;
        }

        if (QDateTime::currentMSecsSinceEpoch() - replyStart > ArpTime)
            //time out
            return false;

//        usleep(100000); // prevent CPU overloading
    }
    return false;
}

ifaddrs*  AdapterAddr::getAdapts() {
    if (!mAdaptList) {
         if (getifaddrs(&mAdaptList) == -1)
            mAdaptList = nullptr;
    }
    return mAdaptList;
}

bool AdapterAddr::getAdaptName(IP4Addr destIp, char name[]) {
    auto netDestIp = htonl(destIp);
    for (auto* adapt = getAdapts(); adapt; adapt = adapt->ifa_next) {
///        printf("+++ getAdaptName %08X %08X fam %d\n",
///               ((sockaddr_in*) adapt->ifa_addr)->sin_addr.s_addr, destIP, adapt->ifa_addr->sa_family);
        if (adapt->ifa_addr && checkFamily(adapt->ifa_addr->sa_family)      // Ethernet
            && ((sockaddr_in*) adapt->ifa_addr)->sin_addr.s_addr == netDestIp) {
            strcpy(name, adapt->ifa_name);
            return true;
        }
    }
    return false;
}

#endif // __linux__

