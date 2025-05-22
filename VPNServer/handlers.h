#ifndef HANDLERS_H
#define HANDLERS_H

#include <memory>

////////#include <winsock2.h>
////////#include <windows.h>

#include <QThread>
#include <QTcpSocket>
#include <QHostAddress>

#include <pcap.h>

#include "ServerData.h"

class ClientSocket : public QObject
{
    Q_OBJECT
public:
    ClientSocket(QTcpSocket* _socket, u_int clientId, QObject *parent = nullptr);

    u_int clientId()            { return mClientId; }

private:
    bool                        updatePacket (IPPacket& _packet);
    void                        onReadyRead();
    u_short                     getServerPort(u_short clientPort);
    std::unique_ptr<QTcpSocket> mSocket = nullptr;
    const u_int                 mClientId = 0;

    QHostAddress virtAdapterIP  {"10.6.7.7"};
};

class RealSender : public QThread
{
    Q_OBJECT
    void run() override;

public:
    ~RealSender()             { closeAdapter(); }
    bool openAdapter();
    void closeAdapter();
    bool updatePacket(IPPacket& _packet);
    bool send(const IPPacket& _packet);

    IPAddr  mGatewayIP     = 0;
    u_char  mAdaptMac  [6] = { 0 };
    u_char  mGatewayMac[6] = { 0 };
    pcap_t* mPcapHandle    = nullptr;

    EthernetVlan2 mEthHeader;  // maximal length of Ethernet header
};


#endif // HANDLERS_H
