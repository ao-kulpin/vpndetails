#ifndef HANDLERS_H
#define HANDLERS_H

#include <memory>

#include <QTcpSocket>
#include <QThread>
#include <QEvent>

#include "ClientData.h"

class VPNSocket : public QObject {
    Q_OBJECT
public:
    VPNSocket(QObject *parent = nullptr);
    bool connectToServer(const QString& _ip, u_int _port, const QHostAddress& _adapter);
    QHostAddress  localAddress();


private slots:
    void onConnected();
    void onReadyRead();

private:
    void sendReceivedPackets();
    void sendPacket(const IPPacket& _packet);
    std::unique_ptr<QTcpSocket> mTcpSocket;

protected:
    bool event(QEvent *event) override;
};

class VirtReceiver : public QThread
{
    Q_OBJECT
    void run() override;

    void wakeSender();

public:
    VirtReceiver();
};

class VirtReceiveEvent: public QEvent {
public:
    static const QEvent::Type EventType = static_cast<QEvent::Type>(QEvent::User + 1);

    VirtReceiveEvent (): QEvent(EventType) {}
};

#endif // HANDLERS_H
