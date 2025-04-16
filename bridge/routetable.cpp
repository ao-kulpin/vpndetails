#include <winsock2.h>  // must go first

#include "routetable.h"
#include "BridgeData.h"

#include <QtEndian>

#include <stdio.h>

RouteTable::RouteTable() {

}

RouteTable::~RouteTable() {

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
    if (GetIpForwardTable(nullptr, &ftSize, 0)) {
        mForwadTable.reset(reinterpret_cast<MIB_IPFORWARDTABLE*> (new BYTE[ftSize]));
        if (!mForwadTable || !GetIpForwardTable(mForwadTable.get(), &ftSize, 0))
            return ftFail();
    }
    else
        return ftFail();

    return updateOldDefaults() && createNewDefault();
}

bool RouteTable::restoreDefaultRoute() {
    return false;
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

bool RouteTable::createNewDefault() {
    MIB_IPFORWARDROW route;
    memset(&route, 0, sizeof route);

    route.dwForwardDest = qToBigEndian(bdata.virtAdapterIP.toIPv4Address());
    route.dwForwardIfIndex = 123;
    route.dwForwardType = 2;
    route.dwForwardProto = MIB_IPPROTO_NETMGMT;
    route.dwForwardAge = 123;

    if (CreateIpForwardEntry(&route) == NO_ERROR)
        return true;
    else {
        printf("CreateIpForwardEntry() fails\n");
        return false;
    }
}

int RouteTable::getIndex(DWORD ip4) {
    return -1;
}

