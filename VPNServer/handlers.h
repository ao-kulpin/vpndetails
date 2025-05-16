#ifndef HANDLERS_H
#define HANDLERS_H

#include <memory>

#include <winsock2.h>
#include <windows.h>

#include <QThread>
#include <QTcpSocket>

class ClientHandler : public QThread
{
    Q_OBJECT
public:
    ClientHandler(qintptr socketDescriptor, u_int clientID, QObject *parent = nullptr);

    void run() override;
private:
    void onReadyRead();
    qintptr                     mSocketDescriptor = 0;
    std::unique_ptr<QTcpSocket> mSocket = nullptr;
    const u_int                 mClientId = 0;
};

#endif // HANDLERS_H
