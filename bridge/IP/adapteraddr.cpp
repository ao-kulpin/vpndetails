#include <stdio.h>
#include "adapteraddr.h"

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

bool AdapterAddr::getGateway(IPAddr adaptIp, IPAddr *gatewayIp) {
    for (auto* adapt = getAdapts(); adapt; adapt = adapt->Next) {
        auto* unic = adapt->FirstUnicastAddress;
        ULONG ip4 = ((sockaddr_in*) unic->Address.lpSockaddr)->sin_addr.S_un.S_addr;

        if (unic->Address.lpSockaddr->sa_family == AF_INET && adaptIp == ip4 && adapt->FirstGatewayAddress) {
            *gatewayIp = ((sockaddr_in*) adapt->FirstGatewayAddress->Address.lpSockaddr)->sin_addr.S_un.S_addr;
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
      if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, mAdaptList.get(), &outBufLen) != NO_ERROR) {
//////////          printf("+++ GetAdaptersAddresses fails 2\n");
          mAdaptList.reset(nullptr);
          return nullptr;
      }
    }
    return mAdaptList.get();
}

