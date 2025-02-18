#include <QCoreApplication>
#include <QDebug>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>

#include <iostream>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


static
std::string getAdapType(DWORD dwType) {
    switch(dwType) {

    case IF_TYPE_OTHER:
        return "other";

    case IF_TYPE_ETHERNET_CSMACD:
        return "ethernet";

    case IF_TYPE_ISO88025_TOKENRING:
        return "token ring";

    case IF_TYPE_PPP:
        return "ppp";

    case IF_TYPE_SOFTWARE_LOOPBACK:
        return "software loopback";

    case IF_TYPE_ATM:
        return "ATM";

    case IF_TYPE_IEEE80211:
        return "IEEE 802.11 wireless";

    case IF_TYPE_TUNNEL:
        return "tunnel";

    case IF_TYPE_IEEE1394:
        return "IEEE 1394(Firewire)";

    case IF_TYPE_PROP_VIRTUAL:
        return "proprietary virtual/internal";

    default:
        return "*** UNKNOWN ***";
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);


    // int i;

    /* Variables used by GetIpAddrTable */
    PMIB_IPADDRTABLE pIPAddrTable = 0;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    // IN_ADDR IPAddr;

    /* Variables used to return error message */
    LPVOID lpMsgBuf;

    // Before calling AddIPAddress we use GetIpAddrTable to get
    // an adapter to which we can add the IP.
    // pIPAddrTable = (MIB_IPADDRTABLE *) malloc(sizeof (MIB_IPADDRTABLE));

    if (true) {
        // Make an initial call to GetIpAddrTable to get the
        // necessary size into the dwSize variable
        if (GetIpAddrTable(0, &dwSize, 0) ==
            ERROR_INSUFFICIENT_BUFFER) {
            free(pIPAddrTable);
            pIPAddrTable = (MIB_IPADDRTABLE *) malloc(dwSize);

        }
        if (pIPAddrTable == NULL) {
            printf("Memory allocation failed for GetIpAddrTable\n");
            exit(1);
        }
    }
    // Make a second call to GetIpAddrTable to get the
    // actual data we want
    if ( (dwRetVal = GetIpAddrTable( pIPAddrTable, &dwSize, 0 )) != NO_ERROR ) {
        printf("GetIpAddrTable failed with error %d\n", dwRetVal);
        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),       // Default language
                          (LPTSTR) & lpMsgBuf, 0, NULL)) {
            printf("\tError: %s", lpMsgBuf);
            LocalFree(lpMsgBuf);
        }
        exit(1);
    }

    printf("\tNum Entries: %ld\n", pIPAddrTable->dwNumEntries);
    for (int i=0; i < (int) pIPAddrTable->dwNumEntries; i++) {

        printf("\n\tInterface Index[%d]:\t%ld\n", i, pIPAddrTable->table[i].dwIndex);

        IN_ADDR IPAddr;
        IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwAddr;
        printf("\tIP Address[%d]:     \t%s\n", i, inet_ntoa(IPAddr) );

        IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwMask;
        printf("\tSubnet Mask[%d]:    \t%s\n", i, inet_ntoa(IPAddr) );
        IPAddr.S_un.S_addr = (u_long) pIPAddrTable->table[i].dwBCastAddr;
        printf("\tBroadCast[%d]:      \t%s (%ld%)\n", i, inet_ntoa(IPAddr), pIPAddrTable->table[i].dwBCastAddr);
        printf("\tReassembly size[%d]:\t%ld\n", i, pIPAddrTable->table[i].dwReasmSize);
        printf("\tType and State[%d]:", i);
        if (pIPAddrTable->table[i].wType & MIB_IPADDR_PRIMARY)
            printf("\tPrimary IP Address");
        if (pIPAddrTable->table[i].wType & MIB_IPADDR_DYNAMIC)
            printf("\tDynamic IP Address");
        if (pIPAddrTable->table[i].wType & MIB_IPADDR_DISCONNECTED)
            printf("\tAddress is on disconnected interface");
        if (pIPAddrTable->table[i].wType & MIB_IPADDR_DELETED)
            printf("\tAddress is being deleted");
        if (pIPAddrTable->table[i].wType & MIB_IPADDR_TRANSIENT)
            printf("\tTransient address");

        MIB_IFROW ifRow = {};
        ifRow.dwIndex = pIPAddrTable->table[i].dwIndex;
        if (GetIfEntry(&ifRow) == NO_ERROR) {
            printf("\n\tInterface Name:  \t%ls", ifRow.wszName);

            printf("\n\tPhysAddr (MAC): \t\t");
            for (int i = 0; i < ifRow.dwPhysAddrLen; ++i) {
                printf("%x ", (unsigned) ifRow.bPhysAddr[i]);
            }

            char descr[MAXLEN_IFDESCR];
            strncpy(descr, (char*) ifRow.bDescr, ifRow.dwDescrLen);
            descr[ifRow.dwDescrLen] = 0;
            printf("\n\tDescription:\t\t%s", descr);

            printf("\n\tType:\t\t\t%s (%d)", getAdapType(ifRow.dwType).c_str(), ifRow.dwType);

            printf("\n");
        }
        else
            printf("\n*** GetIfEntry fails ***\n");
        printf("\n");
    }

    if (pIPAddrTable) {
        free(pIPAddrTable);
        pIPAddrTable = NULL;
    }




    a.exit();
    return 0;
}
