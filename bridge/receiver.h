#ifndef RECEIVER_H
#define RECEIVER_H

#include <winsock2.h>
#include <windows.h>

#include <QThread>

#include <iphlpapi.h>

#include <pcap.h>

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
    bool openAdapter();

    IPAddr  mGatewayIp;
    u_char  mAdaptMac[6]   = { 0 };
    u_char  mGatewayMac[6] = { 0 };
    pcap_t* mPcapHandle     = nullptr;
};

#endif // RECEIVER_H
