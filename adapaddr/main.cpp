#include <QCoreApplication>

#include <iostream>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <locale>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

void PrintNetworkAdapters() {
    ULONG outBufLen = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, 0, &outBufLen);
    std::vector<BYTE> buffer(outBufLen);

    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS, NULL, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &outBufLen) == NO_ERROR) {
        IP_ADAPTER_ADDRESSES* pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        for (IP_ADAPTER_ADDRESSES* pCurrAddresses = pAddresses; pCurrAddresses; pCurrAddresses = pCurrAddresses->Next) {
            char descr[1024];
            wcstombs(descr, pCurrAddresses->Description, sizeof descr);
            std::cout << "Adapter Name: " << pCurrAddresses->AdapterName << std::endl;
            std::cout << "Description: " << descr << std::endl;

            // Получаем IP-адреса
            for (IP_ADAPTER_UNICAST_ADDRESS* pUnicast = pCurrAddresses->FirstUnicastAddress;
                 pUnicast != NULL;
                 pUnicast = pUnicast->Next) {

                char ipStr[INET6_ADDRSTRLEN]; // Достаточно для IPv4 и IPv6
                sockaddr* sa = pUnicast->Address.lpSockaddr;

                if (sa->sa_family == AF_INET) { // IPv4
                    sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(sa);
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, sizeof(ipStr));
                } else if (sa->sa_family == AF_INET6) { // IPv6
                    sockaddr_in6* sa_in6 = reinterpret_cast<sockaddr_in6*>(sa);
                    inet_ntop(AF_INET6, &(sa_in6->sin6_addr), ipStr, sizeof(ipStr));
                }

                std::cout << "IP Address: " << ipStr << std::endl;
            }


            // Выводим шлюз по умолчанию
            for (auto gateway = pCurrAddresses->FirstGatewayAddress; gateway != nullptr; gateway = gateway->Next) {
                char ipStr[INET_ADDRSTRLEN];
                sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(gateway->Address.lpSockaddr);
                inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, sizeof(ipStr));
                std::cout << "Default Gateway: " << ipStr << std::endl;
            }

            // Получаем DNS-серверы
            for (IP_ADAPTER_DNS_SERVER_ADDRESS* dnsServer = pCurrAddresses->FirstDnsServerAddress; dnsServer != nullptr; dnsServer = dnsServer->Next) {
                char dnsStr[INET6_ADDRSTRLEN];
                sockaddr* sa_dns = dnsServer->Address.lpSockaddr;

                if (sa_dns->sa_family == AF_INET) { // IPv4
                    sockaddr_in* sa_in = reinterpret_cast<sockaddr_in*>(sa_dns);
                    inet_ntop(AF_INET, &(sa_in->sin_addr), dnsStr, sizeof(dnsStr));
                } else if (sa_dns->sa_family == AF_INET6) { // IPv6
                    sockaddr_in6* sa_in6 = reinterpret_cast<sockaddr_in6*>(sa_dns);
                    inet_ntop(AF_INET6, &(sa_in6->sin6_addr), dnsStr, sizeof(dnsStr));
                }

                std::cout << "DNS Server " << (sa_dns->sa_family == AF_INET ? "ipv4: " : "ipv6: ") << dnsStr << std::endl;
            }

            std::cout << std::endl;
        }
    } else {
        std::cerr << "Failed to get adapter addresses." << std::endl;
    }
}

static
void printIP(const char* label, const IP_ADDR_STRING* ips) {
    printf("%s", label );
    for( auto ip = ips; ip; ip = ip->Next)
        printf(" %s/%s", ip->IpAddress.String, ip->IpMask.String);
    printf("\n");
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    printf("\n***** get info from GetAdaptersAddresses *****\n\n");
    PrintNetworkAdapters();

    printf("\n***** get info from GetAdaptersInfo *****\n\n");

    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    UINT i;

    /* variables used to print DHCP time info */
    struct tm newtime;
    char buffer[32];
    errno_t error;

    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
        return 1;
    }
    // Make an initial call to GetAdaptersInfo to get
    // the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            return 1;
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        pAdapter = pAdapterInfo;
        while (pAdapter) {
            printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
            printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
            printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
            printf("\tAdapter Addr: \t");
            for (i = 0; i < pAdapter->AddressLength; i++) {
                if (i == (pAdapter->AddressLength - 1))
                    printf("%.2X\n", (int) pAdapter->Address[i]);
                else
                    printf("%.2X-", (int) pAdapter->Address[i]);
            }
            printf("\tIndex: \t%d\n", pAdapter->Index);
            printf("\tType: \t");
            switch (pAdapter->Type) {
            case MIB_IF_TYPE_OTHER:
                printf("Other\n");
                break;
            case MIB_IF_TYPE_ETHERNET:
                printf("Ethernet\n");
                break;
            case MIB_IF_TYPE_TOKENRING:
                printf("Token Ring\n");
                break;
            case MIB_IF_TYPE_FDDI:
                printf("FDDI\n");
                break;
            case MIB_IF_TYPE_PPP:
                printf("PPP\n");
                break;
            case MIB_IF_TYPE_LOOPBACK:
                printf("Loopback\n");
                break;
            case MIB_IF_TYPE_SLIP:
                printf("Slip\n");
                break;
            case IF_TYPE_PROP_VIRTUAL:
                printf("Virtual\n");
                break;
            case IF_TYPE_IEEE80211:
                printf("IEEE80211\n");
                break;
            default:
                printf("Unknown type %ld\n", pAdapter->Type);
                break;
            }

//            printf("\tIP Address: \t%s\n",
//                   pAdapter->IpAddressList.IpAddress.String);
            printIP("\tIP Address: \t", &pAdapter->IpAddressList);

//            printf("\tIP Mask: \t%s\n", pAdapter->IpAddressList.IpMask.String);

//            printf("\tGateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
            printIP("\tGateway: \t", &pAdapter->GatewayList);
            printf("\t***\n");

            if (pAdapter->DhcpEnabled) {
                printf("\tDHCP Enabled: Yes\n");
//                printf("\t  DHCP Server: \t%s\n",
//                       pAdapter->DhcpServer.IpAddress.String);
                printIP("\t  DHCP Server: \t", &pAdapter->DhcpServer);

                printf("\t  Lease Obtained: ");
                /* Display local time */
                error = _localtime32_s(&newtime, (__time32_t*) &pAdapter->LeaseObtained);
                if (error)
                    printf("Invalid Argument to _localtime32_s\n");
                else {
                    // Convert to an ASCII representation
                    error = asctime_s(buffer, 32, &newtime);
                    if (error)
                        printf("Invalid Argument to asctime_s\n");
                    else
                        /* asctime_s returns the string terminated by \n\0 */
                        printf("%s", buffer);
                }

                printf("\t  Lease Expires:  ");
                error = _localtime32_s(&newtime, (__time32_t*) &pAdapter->LeaseExpires);
                if (error)
                    printf("Invalid Argument to _localtime32_s\n");
                else {
                    // Convert to an ASCII representation
                    error = asctime_s(buffer, 32, &newtime);
                    if (error)
                        printf("Invalid Argument to asctime_s\n");
                    else
                        /* asctime_s returns the string terminated by \n\0 */
                        printf("%s", buffer);
                }
            } else
                printf("\tDHCP Enabled: No\n");

            if (pAdapter->HaveWins) {
                printf("\tHave Wins: Yes\n");
                printf("\t  Primary Wins Server:    %s\n",
                       pAdapter->PrimaryWinsServer.IpAddress.String);
                printf("\t  Secondary Wins Server:  %s\n",
                       pAdapter->SecondaryWinsServer.IpAddress.String);
            } else
                printf("\tHave Wins: No\n");
            pAdapter = pAdapter->Next;
            printf("\n");
        }
    } else {
        printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

    }
    if (pAdapterInfo)
        free(pAdapterInfo);

    return 0;

    a.exit();
    return 0;
}
