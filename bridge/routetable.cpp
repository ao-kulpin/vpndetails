#include <winsock2.h>  // must go first
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "routetable.h"
#include "BridgeData.h"

#include <QtEndian>

#include <stdio.h>

RouteTable::RouteTable() :
    mVirtAdapIndex {getIndex(qToBigEndian(bdata.virtAdapterIP.toIPv4Address()))}
{}

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

    return resetVirtMetric() && updateOldDefaults() && createNewDefault();
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
    // printf("+++ updateMetric(%p %d)\n", &oldRoute, metric);
    MIB_IPFORWARDROW newRoute;
    memcpy(&newRoute, &oldRoute, sizeof newRoute);
    newRoute.dwForwardMetric1 = metric;

    int rc = -1;
    if ((rc = SetIpForwardEntry(&newRoute)) == NO_ERROR)
        return true;
    else {
        printf("SetIpForwardEntry() fails rc=%d\n", rc);
        return false;
    }
}

bool RouteTable::updateOldDefaults() {

    for (int ir = 0; ir < mForwadTable->dwNumEntries; ++ir) {
        auto& route = mForwadTable->table[ir];
        if (isDefault(route)) {
            if (!updateMetric(route, route.dwForwardMetric1 + bdata.defaultMetricAdd))
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
    InitializeIpForwardEntry(&route);

    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.NextHop.si_family = AF_INET;
    route.Metric = 0;

    route.InterfaceIndex = mVirtAdapIndex;
    route.DestinationPrefix.PrefixLength = 0;
    route.Age = 0;
    route.Protocol = RouteProtocolNetMgmt;

    int rc = CreateIpForwardEntry2(&route);
    if (rc == NO_ERROR || rc == ERROR_OBJECT_ALREADY_EXISTS) {
        // printf("\n+++ CreateIpForwardEntry2(%d %ld %ld)\n", rc, route.Metric, route.Age);
        return true;
    }
    else {
        printf("CreateIpForwardEntry2() fails rc:%d\n", rc);
        return false;
    }
}

bool RouteTable::deleteNewDefault() {

    MIB_IPFORWARD_ROW2  route = {0};
    InitializeIpForwardEntry(&route);

    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.NextHop.si_family = AF_INET;
    route.Metric = 0;
    route.InterfaceIndex = mVirtAdapIndex;

    int rc = -1;
    if ((rc = DeleteIpForwardEntry2(&route)) == NO_ERROR)
        return true;
    else {
        printf("DeleteIpForwardEntry2() fails rc:%d\n", rc);
        return false;
    }
}

IP_ADAPTER_INFO* RouteTable::getAdapts() {
    if (!mAdapts) {
        auto aiFail = []{
            printf("GetAdaptersInfo() fails\n");
            return nullptr;
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

    return mAdapts.get();
}

bool RouteTable::resetVirtMetric() {
    MIB_IPINTERFACE_ROW row;
    InitializeIpInterfaceEntry(&row);

    row.Family = AF_INET;
    row.InterfaceIndex = mVirtAdapIndex;

    int rc1 = -1;
    if ((rc1 = GetIpInterfaceEntry(&row)) == NO_ERROR) {
        //printf("\n+++ Metric=%d Family=%d Index=%d SitePrefixLength=%ld DisableDefaultRoutes=%d UseAutomaticMetric=%d\n",
        //       row.Metric, row.Family, row.InterfaceIndex,
        //      row.SitePrefixLength, row.DisableDefaultRoutes,
        //       int(row.UseAutomaticMetric));

        row.SitePrefixLength = 0;
        row.UseAutomaticMetric = FALSE; // important !!!
        row.Metric = 0;  // zero metric

        int rc2 = -1;
        if ((rc2 = SetIpInterfaceEntry(&row)) == NO_ERROR)
            return true;
        else {
            printf("SetIpInterfaceEntry() fails rc=%d\n", rc2);
            return false;
        }
    }
    else {
        printf("GetIpInterfaceEntry() fails rc=%d\n", rc1);
        return false;
    }

    return true;
}

int RouteTable::getIndex(DWORD ip4) {
    auto* alist = getAdapts();
    if (!alist)
        return -1;
    for (auto* ad = alist; ad; ad = ad->Next) {
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

