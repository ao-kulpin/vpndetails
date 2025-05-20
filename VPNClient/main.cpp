#include <QCoreApplication>

#include <csignal>

#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

#include "ClientData.h"
#include "handlers.h"

#include "killer.h"
#include "routetable.h"

ClientData cdata; // common data of the application

WinTunLib*                            WinTunLib::mInstance = nullptr;

void signalHandler(int signum) {
    printf("\nTerminated by user\n");
    cdata.haveQuit = true;
    SetEvent(cdata.quitEvent);
    QCoreApplication::quit();
}

static bool
setIPAddress () {
    auto& virtAdapter = cdata.virtAdapter;

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WinTunLib::getAdapterLUID(virtAdapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr =
        htonl(cdata.virtAdapterIP.toIPv4Address());
    AddressRow.OnLinkPrefixLength = cdata.virtAdapterMaskLen;
    AddressRow.DadState = IpDadStatePreferred;
    auto LastError = CreateUnicastIpAddressEntry(&AddressRow);

    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS)
    {
        printf("Failed to set IP address (error=%ld)\n", LastError);
        return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    /// printf("VPNClient!!! thread=%p\n", QThread::currentThread());

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

    auto& virtAdapter = cdata.virtAdapter;
    auto& adapGuid = cdata.adapGuid;
    auto& session = cdata.session;
    virtAdapter = WinTunLib::createAdapter(L"VPNClient", L"Adapter", &adapGuid);

    if (virtAdapter) {
        auto ver = WinTunLib::getDriverVersion();
        printf("Virtual adapter is created. Version %ld.%ld\n", ver >> 16, ver & 0xFF);
    }
    else {
        printf("Can't create the virtual adapter (error=%ld)\n", GetLastError() );
        a.exit(1);
        return 1;
    }

    Killer vak ( [] {
        WinTunLib::closeAdapter(virtAdapter);
        printf("Virtual adapter is closed\n");
    });

    if (!setIPAddress()) {
        return 1;
    }

    session = WinTunLib::startSession(virtAdapter, cdata.ringSize);
    if (session)
        printf("Session is started\n");
    else {
        printf("Can't start the session (error=%ld)\n", GetLastError());
        a.exit(1);
        return 1;
    }

    Killer sek ( [] {
        WinTunLib::endSession(session);
        printf("Session is ended\n");
    });

    RouteTable rtable;

    if (rtable.updateDefaultRoute())
        printf("Route table is updated\n");
    else {
        printf("Can't update the route table\n");
        return 1;
    }

    Killer rtk ( [&] {
        if (rtable.restoreDefaultRoute())
            printf("Route table is restored\n");
        else {
            printf("Can't restore the route table\n");
        }
    });

    cdata.quitEvent = CreateEvent(0, TRUE, FALSE, 0);
    if (!cdata.quitEvent) {
        printf("Can't create quitEvent\n");
        return 1;
    }

    Killer qek ( [&] {
        CloseHandle(cdata.quitEvent);
    });




    //VPNSocket socket;
    cdata.vpnSocket = new VPNSocket;
    if(!cdata.vpnSocket->connectToServer(cdata.serverIP.toString(), cdata.serverPort, cdata.realAdapterIP)) {
        printf("Can't connect to server %s:%d\n", cdata.serverIP.toString().toLocal8Bit().constData(), cdata.serverPort);
        return 1;
    }

    printf("Connected to server %s:%d\n", cdata.serverIP.toString().toLocal8Bit().constData(), cdata.serverPort);

    VirtReceiver vreceiver;
    Killer vrck ( [&] {
        vreceiver.wait();
        printf("Virtual receiver is ended\n");
    });


    printf("Waiting for Ctrl-C ...\n\n");
    std::signal(SIGINT, signalHandler);

    vreceiver.start();

    return a.exec();
}
