#ifndef BRIDGEDATA_H
#define BRIDGEDATA_H

#include <QHostAddress>
#include "wintunlib.h"


class BridgeData {
public:
    WINTUN_ADAPTER_HANDLE virtAdapter   {nullptr};
    const GUID adapGuid                 {0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }};
    QHostAddress virtAdapterIP          {"10.6.7.7"};
    int virtAdapterMaskLen              {24};
    WINTUN_SESSION_HANDLE session       {nullptr};
    int ringSize                        {0x400000};

};

extern BridgeData bdata;

#endif // BRIDGEDATA_H
