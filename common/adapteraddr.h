#ifndef ADAPTERADDR_H
#define ADAPTERADDR_H

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#endif

#ifdef __linux__
#include "vpntypes.h"
#endif

#include <memory>

class AdapterAddr
{
public:
    static
    bool getMacAddress(IPAddr destIP, u_char macAddres[]);
    static
    bool getGatewayMacAddress(IPAddr _destIP, u_char _macAddress[]);

    static
    bool getGatewayIP(IPAddr ip, IPAddr *gatewayIP);

private:

#ifdef _WIN32

    static
    IP_ADAPTER_ADDRESSES* getAdapts();

    static
    std::unique_ptr<IP_ADAPTER_ADDRESSES> mAdaptList;

#endif
};

#endif // ADAPTERADDR_H
