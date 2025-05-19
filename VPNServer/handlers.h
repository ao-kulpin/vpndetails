#ifndef HANDLERS_H
#define HANDLERS_H

#include <memory>

#include <winsock2.h>
#include <windows.h>

#include <QThread>
#include <QTcpSocket>

class ClientSocket : public QObject
{
    Q_OBJECT
public:
    ClientSocket(QTcpSocket* _socket, u_int clientId, QObject *parent = nullptr);

private:
    void onReadyRead();
    std::unique_ptr<QTcpSocket> mSocket = nullptr;
    const u_int                 mClientId = 0;
};

#endif // HANDLERS_H
