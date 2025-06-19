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

#include "vpntypes.h"
#endif

class AdapterAddr
{
public:
    static
    bool getMacAddress(IPAddr destIP, u_char macAddress[]);
    static
    bool getGatewayMacAddress(IPAddr _srcIp, IPAddr _destIp, u_char _macAddress[]);

    static
    bool getGatewayIP(IPAddr ip, IPAddr *gatewayIP);

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
    bool            getAdaptName(IPAddr destIp, char name[]);

    static
    ifaddrs*        mAdaptList;

#endif //__linux__
};

#endif // ADAPTERADDR_H
