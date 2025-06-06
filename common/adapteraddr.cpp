#include <stdio.h>
#include <string.h>
#include "adapteraddr.h"

#ifdef _WIN32

bool AdapterAddr::getMacAddress(IPAddr destIP, u_char macAddress[]) {
    memset(macAddress, 0, 6);
    for (auto* adapt = getAdapts(); adapt; adapt = adapt->Next) {
/////        printf("+++ adapt Name: %s\n", adapt->AdapterName);
        for (auto* unic = adapt->FirstUnicastAddress; unic; unic = unic->Next) {
            ULONG ip4 = ((sockaddr_in*) unic->Address.lpSockaddr)->sin_addr.S_un.S_addr;
/////            printf("+++ getMac ip: %08X macLen: %ld\n", ip4, adapt->PhysicalAddressLength);
            if (unic->Address.lpSockaddr->sa_family == AF_INET && destIP == ip4) {

                if (adapt->PhysicalAddressLength !=6)
                    return false;

                memcpy(macAddress, adapt->PhysicalAddress, 6);
                return true;
            }
        }
    }
    return false;
}

bool AdapterAddr::getGatewayMacAddress(IPAddr _destIP, u_char _macAddress[]) {
    ULONG macAddr[2] = { 0 };
    ULONG phyAddrLen = 6;  /* default to length of six bytes */

    //Send an arp packet
    if (SendARP(_destIP , 0, macAddr, &phyAddrLen) != NO_ERROR || phyAddrLen != 6)
        return false;

    memcpy(_macAddress, macAddr, 6);
    return true;
}

bool AdapterAddr::getGatewayIP(IPAddr adaptIp, IPAddr *gatewayIP) {
    for (auto* adapt = getAdapts(); adapt; adapt = adapt->Next) {
        auto*  unic = adapt->FirstUnicastAddress;
        IPAddr ip4 = ((sockaddr_in*) unic->Address.lpSockaddr)->sin_addr.S_un.S_addr;

        if (unic->Address.lpSockaddr->sa_family == AF_INET && adaptIp == ip4 && adapt->FirstGatewayAddress) {
            *gatewayIP = ((sockaddr_in*) adapt->FirstGatewayAddress->Address.lpSockaddr)->sin_addr.S_un.S_addr;
            return true;
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

bool AdapterAddr::getMacAddress(IPAddr destIP, u_char macAddress[]) {
    memset(macAddress, 0, 6);

    for (auto* adapt = getAdapts(); adapt; adapt = adapt->ifa_next) {
        if (adapt->ifa_addr && adapt->ifa_addr->sa_family == AF_PACKET      // Ethernet
            && ((sockaddr_in*) adapt->ifa_addr)->sin_addr.s_addr == destIP) {
            memcpy(macAddress, adapt->ifa_addr->sa_data, 6);
            return true;
        }
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

#endif // __linux__

