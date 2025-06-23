#ifndef SERVER_H
#define SERVER_H

#include <QTcpServer>

class Server : public QTcpServer
{
    Q_OBJECT
public:
    Server(QObject *parent = nullptr);

private slots:
    void onNewConnection();
    void onAcceptError(QAbstractSocket::SocketError socketError);
    void onDestroyed(QObject *obj);
    void onPendingConnectionAvailable();
};


#endif // SERVER_H
