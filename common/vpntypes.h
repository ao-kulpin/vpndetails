#ifndef VPNTYPES_H
#define VPNTYPES_H

typedef unsigned char   u_char;
typedef unsigned int    u_int;
typedef unsigned int    u_int32;

typedef unsigned long   u_long;

typedef u_int32         IP4Addr;  // not u_long

typedef unsigned long long u_int64;

#ifdef __linux__
const int SOCKET_ERROR = -1;
#endif // __linux__

#endif // VPNTYPES_H
