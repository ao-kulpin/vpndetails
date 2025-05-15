#ifndef SERVERDATA_H
#define SERVERDATA_H

#include <winsock2.h>
#include <windows.h>

#include <atomic>

class ServerData {
public:
    std::atomic<u_int> clientCount = 0;
    u_short serverPort = 55555;
};

extern ServerData sdata;

#endif // SERVERDATA_H
