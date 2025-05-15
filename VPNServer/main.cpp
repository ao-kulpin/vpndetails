#include <QCoreApplication>
#include <QTcpServer>
#include <QTcpSocket>

#include <csignal>

#include "ServerData.h"
#include "handlers.h"

ServerData sdata; // common data of the application

void signalHandler(int signum) {
    printf("\nTerminated by user\n");
    //bdata.haveQuit = true;
    //SetEvent(bdata.quitEvent);
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
        QTcpSocket *clientSocket = nextPendingConnection();
        ClientHandler *handler = new ClientHandler(clientSocket->socketDescriptor(), ++sdata.clientCount);
        connect(handler, &QThread::finished, handler, &QObject::deleteLater);
        handler->start();
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

    printf("Waiting for Ctrl-C ...\n\n");

    std::signal(SIGINT, signalHandler);

    return a.exec();
}

#include "main.moc"
