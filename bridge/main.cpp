#include <QCoreApplication>
#include <QDebug>
#include <QHostAddress>
#include <QtEndian>
#include <stdio.h>

#include <csignal>

#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>


#include "bridgedata.h"
#include "killer.h"
#include "routetable.h"
#include "receiver.h"

BridgeData bdata; // common data of the application

WinTunLib* WinTunLib::mInstance = nullptr;

void signalHandler(int signum) {
    printf("\nTerminated by user\n");
    bdata.haveQuit = true;
    SetEvent(bdata.quitEvent);
    QCoreApplication::quit();
}

static bool
setIPAddress () {
    auto& virtAdapter = bdata.virtAdapter;

    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WinTunLib::getAdapterLUID(virtAdapter, &AddressRow.InterfaceLuid);
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr =
                qToBigEndian(bdata.virtAdapterIP.toIPv4Address());
    AddressRow.OnLinkPrefixLength = bdata.virtAdapterMaskLen;
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

    if (argc > 1)
        bdata.realAdapterIP = QHostAddress(argv[1]);

    printf("Bridge IP: %s\n", bdata.realAdapterIP.toString().toStdString().c_str());

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

    auto& virtAdapter = bdata.virtAdapter;
    auto& adapGuid = bdata.adapGuid;
    auto& session = bdata.session;
    virtAdapter = WinTunLib::createAdapter(L"Bridge", L"Adapter", &adapGuid);

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
        a.exit(1);
        return 1;
    }

    session = WinTunLib::startSession(virtAdapter, bdata.ringSize);
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

// #if 0
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
//#endif

    bdata.quitEvent = CreateEvent(0, TRUE, FALSE, 0);
    if (!bdata.quitEvent) {
        printf("Can't create quitEvent\n");
        return 1;
    }

    Killer qek ( [&] {
        CloseHandle(bdata.quitEvent);
    });

    VirtReceiver vreceiver;
    vreceiver.start();

    Killer vrck ( [&] {
        vreceiver.wait();
        printf("Virtual receiver is ended\n");
    });

    RealSender rsender;
    if (!rsender.openAdapter()) {
        printf("Can't open real adapter\n");
        a.exit(1);
        return 1;
    }

    rsender.start();

    Killer rsk ( [&] {
        rsender.wait();
        printf("Real sender is ended\n");
    });

    WSADATA wsadata;
    int rc = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (rc) {
        printf("WSAStartup fails: %d", rc);
    }

    printf("Waiting for Ctrl-C ...\n");

    std::signal(SIGINT, signalHandler);

    return a.exec();
}
