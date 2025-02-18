#include <QCoreApplication>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static
void print_pcap_addr(pcap_addr_t *addr) {
    char addr_str[INET6_ADDRSTRLEN];
    char netmask_str[INET6_ADDRSTRLEN];
    char broadaddr_str[INET6_ADDRSTRLEN];
    char dstaddr_str[INET6_ADDRSTRLEN];

    if (addr->addr) {
        if (inet_ntop(addr->addr->sa_family,
                      &((struct sockaddr_in *)addr->addr)->sin_addr,
                      addr_str, sizeof(addr_str))) {
            printf(" Address: %s", addr_str);
        }
    }

    if (addr->netmask) {
        if (inet_ntop(addr->netmask->sa_family,
                      &((struct sockaddr_in *)addr->netmask)->sin_addr,
                      netmask_str, sizeof(netmask_str))) {
            printf(" Netmask: %s", netmask_str);
        }
    }

    if (addr->broadaddr) {
        if (inet_ntop(addr->broadaddr->sa_family,
                      &((struct sockaddr_in *)addr->broadaddr)->sin_addr,
                      broadaddr_str, sizeof(broadaddr_str))) {
            printf(" Broadcast Address: %s", broadaddr_str);
        }
    }
    if (addr->dstaddr) {
        if (inet_ntop(addr->broadaddr->sa_family,
                      &((struct sockaddr_in *)addr->broadaddr)->sin_addr,
                      dstaddr_str, sizeof(dstaddr_str))) {
            printf(" Destination Address: %s", dstaddr_str);
        }
    }
}

static
void print_flags(bpf_u_int32 flags) {
    if (flags & PCAP_IF_LOOPBACK)
        printf(" +loopback");
    else
        printf(" -loopback");

    if (flags & PCAP_IF_UP)
        printf(" +up");
    else
        printf(" -up");

    if (flags & PCAP_IF_RUNNING)
        printf(" +running");
    else
        printf(" -running");

    if (flags & PCAP_IF_WIRELESS)
        printf(" +wireless");
    else
        printf(" -wireless");

    switch (flags & PCAP_IF_CONNECTION_STATUS) {
    case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
        printf(" unknown stat");
        break;

    case PCAP_IF_CONNECTION_STATUS_CONNECTED:
        printf(" connect stat");
        break;

    case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
        printf(" disconnect stat");
            break;

    case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
        printf(" not app stat");
            break;

    default:
        assert(false);
        break;
    }
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    pcap_if_t *alldevs = 0;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE]; ////////////////////



    // Получаем список доступных устройств
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Ошибка получения списка устройств: %s\n", errbuf);
        return 1;
    }

    printf("Network adapters:\n");
    int devNum = 0;
    for (pcap_if_t* device = alldevs; device != NULL; device = device->next) {
        printf("\n\n%d. %s", ++devNum, device->name);
        printf("\n\t description: %s", device->description);

        printf("\n\t flags: %08X", device->flags);
        print_flags(device->flags);

        printf("\n\t addresses");
        int addrNum = 0;
        for (auto addr = device->addresses; addr; addr = addr->next) {
            printf("\n\t\t%d.", ++ addrNum);
            print_pcap_addr(addr);
        }

    }
    printf ("\n\n");

    a.exit();
    return 0;
}
