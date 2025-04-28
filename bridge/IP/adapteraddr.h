#ifndef ADAPTERADDR_H
#define ADAPTERADDR_H

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

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
    static
    IP_ADAPTER_ADDRESSES* getAdapts();

    static
    std::unique_ptr<IP_ADAPTER_ADDRESSES> mAdaptList;
};

#endif // ADAPTERADDR_H
