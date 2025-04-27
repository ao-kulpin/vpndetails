#include "receiver.h"
#include "BridgeData.h"
#include "killer.h"
#include "adapteraddr.h"

#include <QMutexLocker>
#include <iphlpapi.h>
#include <QtEndian>

VirtReceiver::VirtReceiver() {}

static void wakeSender() {
    if (bdata.virtReceiveMutex.tryLock(200)) {
        bdata.virtReceiveWC.wakeAll();
        bdata.virtReceiveMutex.unlock();
    }
}

void VirtReceiver::run() {
    HANDLE events[] = {bdata.quitEvent, WinTunLib::getReadWaitEvent(bdata.session)};

    int packetCount = 0;
    while(!bdata.haveQuit) {
        DWORD packetSize = 0;
        BYTE* packet = WinTunLib::receivePacket(bdata.session, &packetSize);
        if (packet) {
            {
                QMutexLocker vrl (&bdata.virtReceiveMutex);

                if (++packetCount % 50 == 0)
                    printf("%d packets received\n", packetCount);

                bdata.virtReceiveQueue.push(std::make_unique<IPPacket>(packet, packetSize));
                bdata.virtReceiveWC.wakeAll();
            }

            WinTunLib::releaseReceivePacket(bdata.session, packet);

        }
        else {
            switch (GetLastError())
            {
            case ERROR_NO_MORE_ITEMS:
                DWORD wres = WaitForMultipleObjects(2, events, FALSE, INFINITE);
                switch (wres) {
                case WAIT_OBJECT_0:
                case WAIT_OBJECT_0 + 1:
                    continue;
                default:
                    printf("\nError: Receiver fails\n");
                    return;
                }
            }
        }
    }
    printf("Receiver thread edned (%d packets handled)\n", packetCount);
    wakeSender();
}

static
void getGatewayMacAddress(ULONG destip, u_char *mac) {

    ULONG MacAddr[2] = { 0 };
    ULONG PhyAddrLen = 6;  /* default to length of six bytes */

    //Send an arp packet
    DWORD ret = SendARP(destip , 0, MacAddr, &PhyAddrLen);
    printf("+++ SendARP %ld [%08lX %08lX]\n", ret, MacAddr[0], MacAddr[1]);

    //Prepare the mac address
    if(PhyAddrLen) {

        auto* bMacAddr = (u_char*) &MacAddr;
        for (int i = 0; i < PhyAddrLen; i++)
        {
            mac[i] = bMacAddr[i];
        }
    }
}

void getGateway(IPAddr ip, char *sgatewayip, IPAddr *gatewayip)
{
    ULONG outBufLen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, 0, &outBufLen);

///    char *pAdapterInfo = calloc(1, outBufLen);
    std::unique_ptr<u_char> pAdapterInfo (new u_char[outBufLen]);
    IP_ADAPTER_ADDRESSES*   AdapterInfo;
//////////    ULONG OutBufLen = sizeof(pAdapterInfo) ;

    ////GetAdaptersInfo2((PIP_ADAPTER_INFO) pAdapterInfo, &OutBufLen);
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, (PIP_ADAPTER_ADDRESSES) pAdapterInfo.get(), &outBufLen) == NO_ERROR) {

        for (AdapterInfo = (IP_ADAPTER_ADDRESSES*) pAdapterInfo.get(); AdapterInfo;
             AdapterInfo = AdapterInfo->Next)	{
            IP_ADAPTER_UNICAST_ADDRESS* pUnicast = AdapterInfo->FirstUnicastAddress;
            struct sockaddr* sa = pUnicast->Address.lpSockaddr;

            if (ip == ((struct sockaddr_in*)sa)->sin_addr.s_addr && AdapterInfo->FirstGatewayAddress)
            {
                strcpy(sgatewayip,
                       inet_ntoa(((struct sockaddr_in*) AdapterInfo->FirstGatewayAddress->Address.lpSockaddr)->sin_addr));
                break;
            }
        }
    }

    *gatewayip = inet_addr(sgatewayip);
///////////    free(pAdapterInfo);
}


void RealSender::run() {
    int packetCount = 0;

    while (true) {
        auto& inputQueue = bdata.virtReceiveQueue;
        auto& inputWC = bdata.virtReceiveWC;
        auto& mutex = bdata.virtReceiveMutex;
        auto& haveQuit = bdata.haveQuit;

        QMutexLocker vrl (&mutex);

        while (!haveQuit && inputQueue.empty())
            inputWC.wait(&mutex);

        if (haveQuit)
            break; // end of thread

        IPPacket packet (*inputQueue.front());

        inputQueue.pop();

        if (++packetCount % 50 == 0)
            printf("%d packets sent\n", packetCount);
    }

    printf("Sender thread edned (%d packets handled)\n", packetCount);
}

bool RealSender::openAdapter() {
    /* Retrieve the device list */
    pcap_if_t *alldevs = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE+1];

    if (pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf)) {
        printf("pcap_init fails: %s\n", errbuf);
        return false;
    }

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("pcap_findalldevs fails: %s\n", errbuf);
        return false;
    }

    Killer adk ([&] {
        pcap_freealldevs(alldevs);
    });

//#if 0
    const IPAddr   realIp    = qToBigEndian(bdata.realAdapterIP.toIPv4Address());
    const QString realIpStr = bdata.realAdapterIP.toString();
    printf("+++ realIp: %s %08lX\n", realIpStr.toUtf8().constData(), realIp);

    QString devName;
    bool found = false;
    u_char mac[6] = {0};
    for (auto* dev = alldevs; !found && dev; dev = dev->next) {
        for (auto* ap = dev->addresses; !found && ap; ap = ap->next) {
            ULONG ip4 = ((sockaddr_in*) ap->addr)->sin_addr.S_un.S_addr;
            printf("+++ ip4: %08lX\n",  ip4);
            if(ap->addr->sa_family == AF_INET && realIp == ip4) {
                char b[64];
                devName = dev->name;
                AdapterAddr::getMacAddress(realIp, mAdaptMac);

                auto& m = mAdaptMac;
                printf("+++ mac: %02x %02x %02x %02x %02x %02x\n", m[0], m[1], m[2], m[3], m[4], m[5]);

                AdapterAddr::getGateway(realIp, &mGatewayIp);
                printf("+++ gatewayIP:%08X\n", mGatewayIp);
///////                AdapterAddr::getMacAddress(mGatewayIp, mGatewayMac);
                getGatewayMacAddress(mGatewayIp, mGatewayMac);

                auto& gm = mGatewayMac;
                printf("+++ gateway mac: %02x %02x %02x %02x %02x %02x\n", gm[0], gm[1], gm[2], gm[3], gm[4], gm[5]);
                found = true;
            }
        }
    }
//#endif

//#if 0
    mPcapHandle = pcap_open_live(devName.toUtf8().constData(), // name of the device
                             0,     // portion of the packet to capture. 0 == no capture.
                             0,     // non-promiscuous mode
                             1000,	// read timeout
                             errbuf	// error buffer
                                 );
    if (!mPcapHandle) {
        printf("pcap_open_live fails: %s\n", errbuf);
        return false;
    }
//#endif

    return true;
}

