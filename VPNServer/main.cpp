#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>

#include <csignal>

#include "ServerData.h"
#include "handlers.h"
#include "killer.h"
#include "adapteraddr.h"

ServerData sdata; // common data of the application

std::unique_ptr<IP_ADAPTER_ADDRESSES> AdapterAddr::mAdaptList;

void signalHandler(int signum) {
    printf("\nTerminated by user\n");
    sdata.haveQuit = true;

    if (sdata.clientReceiveMutex.tryLock(200)) {
        sdata.clientReceiveWC.wakeAll();
        sdata.clientReceiveMutex.unlock();
    }

    QCoreApplication::quit();
}

class Server : public QTcpServer
{
    Q_OBJECT
public:
    Server(QObject *parent = nullptr) : QTcpServer(parent) {
        connect(this, &QTcpServer::newConnection, this, &Server::onNewConnection);
    }

private slots:
    void onNewConnection() {
        printf("Client connected...\n");
        auto *sock = new ClientSocket(nextPendingConnection(), ++sdata.clientCount);
        sdata.socketMap[sock->clientId()] = sock;
    }
};

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    if (argc > 1)
        sdata.serverPort = strtol(argv[1], 0, 10);

    Server server;

    if (!server.listen(QHostAddress::Any, sdata.serverPort)) {
        printf("Server can't start: %s\n", server.errorString().toLocal8Bit().constData());
        return 1;
    }

    printf("Server is litening port %d\n", sdata.serverPort);
//#if 0

    RealSender rsender;
    if (rsender.openAdapter())
        printf("Real adapter %s is open\n", sdata.realAdapterIP.toString().toStdString().c_str());
    else {
        printf("Can't open real adapter\n");
        return 1;
    }

    Killer rsk ( [&] {
        rsender.wait();
        rsender.closeAdapter();
        printf("Real sender is ended\n");
    });

    RealReceiver rreceiver;
    Killer rrck ([&]{
        rreceiver.wait();
        printf("Real receiver is ended\n");
    });
//#endif

    printf("Waiting for Ctrl-C ...\n\n");

    std::signal(SIGINT, signalHandler);

    rsender.start();
    rreceiver.start();

    return a.exec();
}

#include "main.moc"
