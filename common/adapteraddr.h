#ifndef ADAPTERADDR_H
#define ADAPTERADDR_H

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <memory>
#endif

#ifdef __linux__
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>
#endif

#include "vpntypes.h"


class AdapterAddr
{
public:
    static
    bool getMacAddress(IP4Addr destIP, u_char macAddress[]);
    static
    bool getGatewayMacAddress(IP4Addr _srcIp, IP4Addr _destIp, u_char _macAddress[]);

    static
    bool getGatewayIP(IP4Addr ip, IP4Addr *gatewayIP);

private:

#ifdef _WIN32

    static
    IP_ADAPTER_ADDRESSES* getAdapts();

    static
    std::unique_ptr<IP_ADAPTER_ADDRESSES> mAdaptList;

#endif // _WIN32

#ifdef __linux__

    static
    ifaddrs*        getAdapts();
    static
    bool            getAdaptName(IP4Addr destIp, char name[]);

    static
    ifaddrs*        mAdaptList;

#endif //__linux__
};

#endif // ADAPTERADDR_H
