#include <QCoreApplication>

#include "ClientData.h"
#include "handlers.h"

ClientData cdata; // common data of the application

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    if (argc > 1)
      cdata.serverIP = QHostAddress(argv[1]);

    if (argc > 2)
        cdata.serverPort = strtoul(argv[2], 0, 10);

    VPNSocket socket;
    if(!socket.connectToServer(cdata.serverIP.toString(), cdata.serverPort)) {
        printf("Can't connect to server %s:%d\n", cdata.serverIP.toString().toLocal8Bit().constData(), cdata.serverPort);
        return 1;
    }

    printf("Connected to server %s:%d\n", cdata.serverIP.toString().toLocal8Bit().constData(), cdata.serverPort);

    return a.exec();
}
