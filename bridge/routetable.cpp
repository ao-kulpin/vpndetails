#include <winsock2.h>  // must go first
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "routetable.h"
#include "BridgeData.h"

#include <QtEndian>

#include <stdio.h>

RouteTable::RouteTable() {

}

RouteTable::~RouteTable() {
    restoreDefaultRoute();
}

bool RouteTable::updateDefaultRoute() {
    if (mForwadTable) {
        printf("Route table is updated already\n");
        return false;
    }

    auto ftFail = []{
        printf("GetIpForwardTable() fails\n");
        return false;
    };

    DWORD ftSize = 0;
    if (GetIpForwardTable(nullptr, &ftSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
        mForwadTable.reset(reinterpret_cast<MIB_IPFORWARDTABLE*> (new BYTE[ftSize]));
        if (!mForwadTable || GetIpForwardTable(mForwadTable.get(), &ftSize, 0) != NO_ERROR)
            return ftFail();
    }
    else
        return ftFail();

    return /*updateOldDefaults() && */ createNewDefault();
}

bool RouteTable::restoreDefaultRoute() {
    if (!mForwadTable)
        return true;

    auto rv = deleteNewDefault() && restoreOldDefaults();
    mForwadTable.reset();
    mAdapts.reset();
    return rv;
}

static inline
    bool isDefault(const MIB_IPFORWARDROW& route) {
    return route.dwForwardDest == 0 && route.dwForwardMask == 0;
}

bool updateMetric(const MIB_IPFORWARDROW& oldRoute, int metric) {
    MIB_IPFORWARDROW newRoute;
    memcpy(&newRoute, &oldRoute, sizeof newRoute);
    newRoute.dwForwardMetric1 = metric;

    if (SetIpForwardEntry(&newRoute) == NO_ERROR)
        return true;
    else {
        printf("SetIpForwardEntry() fails\n");
        return false;
    }
}

bool RouteTable::updateOldDefaults() {

    for (int ir = 0; ir < mForwadTable->dwNumEntries; ++ir) {
        auto& route = mForwadTable->table[ir];
        if (isDefault(route)) {
            if (!updateMetric(route, bdata.oldDefaultMetric))
                return false;

        }
    }

    return true;
}
bool RouteTable::restoreOldDefaults() {

    for (int ir = 0; ir < mForwadTable->dwNumEntries; ++ir) {
        auto& route = mForwadTable->table[ir];
        if (isDefault(route)) {
            if (!updateMetric(route, route.dwForwardMetric1))
                return false;
        }
    }

    return true;
}

bool RouteTable::createNewDefault() {
    MIB_IPFORWARD_ROW2  route = {0};
    memset(&route, 0, sizeof route);
    InitializeIpForwardEntry(&route);
    ///
    ///
    //WinTunLib::getAdapterLUID(bdata.virtAdapter, &route.InterfaceLuid);

    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.NextHop.si_family = AF_INET;
    route.Metric = 12;

    route.InterfaceIndex = getIndex(qToBigEndian(bdata.virtAdapterIP.toIPv4Address()));
    route.DestinationPrefix.PrefixLength = 0;
    route.Age = 456;
    route.Protocol = RouteProtocolNetMgmt;

#if 0
    route.dwForwardDest     = 0;
    route.dwForwardNextHop  = qToBigEndian(bdata.virtAdapterIP.toIPv4Address());
    route.dwForwardIfIndex  = getIndex(route.dwForwardNextHop);
    route.dwForwardType     = 3;
    route.dwForwardProto    = MIB_IPPROTO_NETMGMT;
    ///////////route.dwForwardAge      = 123;
#endif

    int rc = CreateIpForwardEntry2(&route);
    if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS) {
        printf("\n+++ CreateIpForwardEntry2(%d %ld %ld)\n", rc, route.Metric, route.Age);
        return true;
    }
    else {
        printf("CreateIpForwardEntry2() fails rc:%d\n", rc);
        return false;
    }
}

bool RouteTable::deleteNewDefault() {
#if 0
    MIB_IPFORWARDROW route;
    memset(&route, 0, sizeof route);

    route.dwForwardDest     = qToBigEndian(bdata.virtAdapterIP.toIPv4Address());
    route.dwForwardIfIndex  = getIndex(route.dwForwardDest);
    route.dwForwardType     = 2;
    route.dwForwardProto    = MIB_IPPROTO_NETMGMT;
    route.dwForwardAge      = 123;

    if (DeleteIpForwardEntry(&route) == NO_ERROR)
        return true;
    else {
        printf("DeleteIpForwardEntry() fails\n");
        return false;
    }
#endif

    MIB_IPFORWARD_ROW2  route = {0};
    InitializeIpForwardEntry(&route);
    WinTunLib::getAdapterLUID(bdata.virtAdapter, &route.InterfaceLuid);

    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.NextHop.si_family = AF_INET;
    route.Metric = 0;

    route.InterfaceIndex = getIndex(qToBigEndian(bdata.virtAdapterIP.toIPv4Address()));

    int rc = -1;
    if ((rc = DeleteIpForwardEntry2(&route)) == NO_ERROR)
        return true;
    else {
        printf("DeleteIpForwardEntry2() fails rc:%d\n", rc);
        return false;
    }



}


int RouteTable::getIndex(DWORD ip4) {
    if (!mAdapts) {
        auto aiFail = []{
            printf("GetAdaptersInfo() fails\n");
            return -1;
        };

        DWORD adaptSize = 0;
        switch (GetAdaptersInfo(nullptr, &adaptSize)) {
        default:
            return aiFail();

        case NO_ERROR:
        case ERROR_BUFFER_OVERFLOW:
            break;
        }

        mAdapts.reset(reinterpret_cast<IP_ADAPTER_INFO*>(new BYTE[adaptSize]));
        if (!mAdapts || GetAdaptersInfo(mAdapts.get(), &adaptSize) != NO_ERROR) {
            mAdapts.reset();
            return aiFail();
        }
    }

    for (auto* ad = mAdapts.get(); ad; ad = ad->Next) {
        for(auto* ips = &ad->IpAddressList; ips; ips = ips->Next) {
            in_addr ia;
            if (inet_pton(AF_INET, ips->IpAddress.String, &ia) <= 0)
                return -1;

            if (ia.S_un.S_addr == ip4)
                return ad->Index;
        }
    }

    return -1;
}

