#ifndef RECEIVER_H
#define RECEIVER_H

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <QThread>

#include <pcap.h>

#include "protocol.h"

class VirtReceiver : public QThread
{
    Q_OBJECT
    void run() override;

public:
    VirtReceiver();
};

class RealSender : public QThread
{
    Q_OBJECT
    void run() override;

public:
    ~RealSender()             { closeAdapter(); }
    bool openAdapter();
    void closeAdapter();
    void updatePacket(IPPacket& _packet);
    bool send(const IPPacket& _packet);

    IPAddr  mGatewayIP     = 0;
    u_char  mAdaptMac  [6] = { 0 };
    u_char  mGatewayMac[6] = { 0 };
    pcap_t* mPcapHandle    = nullptr;

    EthernetVlan2 mEthHeader;  // maximal length of Ethernet header
};

#endif // RECEIVER_H
