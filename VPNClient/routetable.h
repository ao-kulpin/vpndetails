#ifndef ROUTETABLE_H
#define ROUTETABLE_H

#include <QScopedPointer>
#include <iphlpapi.h>

class RouteTable
{
public:
    RouteTable();
    ~RouteTable();

    bool updateDefaultRoute();
    bool restoreDefaultRoute();

private:
    bool updateOldDefaults();
    bool restoreOldDefaults();
    bool createNewDefault();
    bool createServerRoute();
    bool deleteNewDefault();
    bool deleteServerRoute();
    int  getIndex(DWORD ip4);
    bool resetVirtMetric();
    IP_ADAPTER_INFO* getAdapts();

    QScopedPointer<MIB_IPFORWARDTABLE>  mForwadTable;
    QScopedPointer<IP_ADAPTER_INFO>     mAdapts;
};

#endif // ROUTETABLE_H
