#ifndef HANDLERS_H
#define HANDLERS_H

#include <memory>

////////#include <winsock2.h>
////////#include <windows.h>

#include <QThread>
#include <QEvent>
#include <QTcpSocket>
#include <QHostAddress>

#include <pcap.h>

#include "ServerData.h"
#include "inputreader.h"

class ClientSocket : public QObject
{
    Q_OBJECT
public:
    ClientSocket(QTcpSocket* _socket, u_int clientId, QObject *parent = nullptr);

    void takeFromReceiver(IPPacket& _packet);

    u_int clientId()            { return mClientId; }
    QHostAddress                localAddress();
private:
    bool                        updateClientPacket (IPPacket& _packet);
    bool                        updateServerPacket (IPPacket& _packet);
    u_short                     getClientPort(u_short serverPort);
    u_short                     getServerPort(u_short clientPort, bool _listen);
    void                        sendReceivedPackets();
    void                        sendServerPacket(const IPPacket& _packet);
    void                        wakeClient();

    std::unique_ptr<QTcpSocket> mSocket = nullptr;
    const u_int                 mClientId = 0;

    u_int                       mSentServerPackCount = 0;
    u_int64                     mSentServerPackSize = 0;

    QHostAddress virtAdapterIP  {"10.6.7.7"};

    using QueueElemType = std::unique_ptr<IPPacket>;
    std::queue<QueueElemType>    mReceiveQueue;
    QMutex                       mReceiveMutex;
    InputReader                  mInputReader;

protected:
    bool event(QEvent *event) override;

private slots:
    void        onReadyRead();
    void        onError(QAbstractSocket::SocketError socketError);
    void        onDisconnected();
    void        onPeerRequest(const VpnHeader* _request);
};

class ClientReceiveEvent: public QEvent {
    /// Q_OBJECT
public:
    static const QEvent::Type EventType = static_cast<QEvent::Type>(QEvent::User + 1);

    ClientReceiveEvent (): QEvent(EventType) {}
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
    void createDummySocket(unsigned _port);

    IP4Addr mGatewayIP     = 0;
    u_char  mAdaptMac  [6] = { 0 };
    u_char  mGatewayMac[6] = { 0 };
    pcap_t* mPcapHandle    = nullptr;

    EthernetVlan2 mEthHeader;  // maximal length of Ethernet header
};

class RealReceiver : public QThread
{
    Q_OBJECT
    void    run() override;

    void    pcapHandler(const pcap_pkthdr *header, const u_char *pkt_data);

    ClientSocket* findTargetClient(const IPPacket& _packet);

    u_int   mPacketCount = 0;
    u_int64 mPacketSize  = 0;
    pcap_t* mPcapHandle  = nullptr;

public:

    friend
        void    realReceiveHandler(u_char *param, const pcap_pkthdr *header, const u_char *pkt_data);
};

class RawSockReceiver : public QThread
{
    Q_OBJECT
    void run() override;
};

#endif // HANDLERS_H
