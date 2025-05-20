#ifndef HANDLERS_H
#define HANDLERS_H

#include <memory>

#include <QTcpSocket>

#include "ClientData.h"

class VPNSocket : public QObject {
    Q_OBJECT
public:
    VPNSocket(QObject *parent = nullptr);
    bool connectToServer(const QString& _ip, u_int _port, const QHostAddress& _adapter);

private slots:
    void onConnected();
    void onReadyRead();

private:
    std::unique_ptr<QTcpSocket> mTcpSocket;
};


#endif // HANDLERS_H
