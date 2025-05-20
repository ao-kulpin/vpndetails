#include <QCoreApplication>

#include <csignal>

#include "ClientData.h"
#include "handlers.h"

#include "killer.h"

ClientData cdata; // common data of the application

WinTunLib*                            WinTunLib::mInstance = nullptr;

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

    if (argc > 3)
        cdata.realAdapterIP = QHostAddress(argv[3]);

    WSADATA wsadata;
    int rc = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (rc) {
        printf("WSAStartup fails: %d", rc);
        return 1;
    }

    if(WinTunLib::isLoaded())
        printf("wintun.dll is loaded\n");
    else {
        printf("Can't load wintun.dll\n");
        a.exit(1);
        return 1;
    }

    Killer wtlk ( [] {
        WinTunLib::unload();
        printf("wintun.dll is unloaded\n");
    });


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
