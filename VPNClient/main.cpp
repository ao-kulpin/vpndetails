#include <QCoreApplication>

#include <csignal>

#include "ClientData.h"
#include "handlers.h"

ClientData cdata; // common data of the application

void signalHandler(int signum) {
    printf("\nTerminated by user\n");
    //bdata.haveQuit = true;
    //SetEvent(bdata.quitEvent);
    QCoreApplication::quit();
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    if (argc > 1)
      cdata.serverIP = QHostAddress(argv[1]);

    if (argc > 2)
      cdata.realAdapterIP = QHostAddress(argv[2]);

    if (argc > 2)
        cdata.serverPort = strtoul(argv[2], 0, 10);

    VPNSocket socket;
    if(!socket.connectToServer(cdata.serverIP.toString(), cdata.serverPort, cdata.realAdapterIP)) {
        printf("Can't connect to server %s:%d\n", cdata.serverIP.toString().toLocal8Bit().constData(), cdata.serverPort);
        return 1;
    }

    printf("Connected to server %s:%d\n", cdata.serverIP.toString().toLocal8Bit().constData(), cdata.serverPort);

    printf("Waiting for Ctrl-C ...\n\n");
    std::signal(SIGINT, signalHandler);


    return a.exec();
}
