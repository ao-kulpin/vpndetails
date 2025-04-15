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

BridgeData bdata; // common data of the application

WinTunLib* WinTunLib::mInstance = nullptr;

void signalHandler(int signum) {
    printf("\nTerminated by user\n");
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





    printf("Waiting for Ctrl-C ...\n");

    std::signal(SIGINT, signalHandler);

    return a.exec();
}
