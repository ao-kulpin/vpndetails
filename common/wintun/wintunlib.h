#ifndef WINTUNLIB_H
#define WINTUNLIB_H

#include "wintun.h"

class WinTunLib {
public:
    static WINTUN_ADAPTER_HANDLE
        createAdapter(_In_z_ LPCWSTR Name, _In_z_ LPCWSTR TunnelType, _In_opt_ const GUID *RequestedGUID) {
            return getInstance()->WintunCreateAdapter(Name, TunnelType, RequestedGUID);
        }

    static void
        closeAdapter(_In_opt_ WINTUN_ADAPTER_HANDLE Adapter) {
            getInstance()->WintunCloseAdapter(Adapter);
        }

    static WINTUN_ADAPTER_HANDLE
        openAdapter(_In_z_ LPCWSTR Name) {
        return getInstance()->WintunOpenAdapter(Name);
        }

    static void
        getAdapterLUID(_In_ WINTUN_ADAPTER_HANDLE Adapter, _Out_ NET_LUID *Luid) {
            getInstance()->WintunGetAdapterLUID(Adapter, Luid);
        }

    static DWORD
        getDriverVersion() {
            return getInstance()->WintunGetRunningDriverVersion();
        }

    static void
        deleteDriver() {
            getInstance()->WintunDeleteDriver();
        }

    static void
        setLogger(_In_ WINTUN_LOGGER_CALLBACK NewLogger) {
            getInstance()->WintunSetLogger(NewLogger);
        }

    static WINTUN_SESSION_HANDLE
        startSession(_In_ WINTUN_ADAPTER_HANDLE Adapter, _In_ DWORD Capacity) {
            return getInstance()->WintunStartSession(Adapter, Capacity);
        }

    static void
        endSession(_In_ WINTUN_SESSION_HANDLE Session) {
            getInstance()->WintunEndSession(Session);
        }

    static HANDLE
        getReadWaitEvent(_In_ WINTUN_SESSION_HANDLE Session) {
            return getInstance()->WintunGetReadWaitEvent(Session);
        }

    static BYTE*
        receivePacket(_In_ WINTUN_SESSION_HANDLE Session, _Out_ DWORD *PacketSize) {
            return getInstance()->WintunReceivePacket(Session, PacketSize);
        }

    static void
        releaseReceivePacket(_In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet) {
            return getInstance()->WintunReleaseReceivePacket(Session, Packet);
        }

    static BYTE*
        allocateSendPacket(_In_ WINTUN_SESSION_HANDLE Session, _In_ DWORD PacketSize) {
            return getInstance()->WintunAllocateSendPacket(Session, PacketSize);
        }
    static void
        sendPacket(_In_ WINTUN_SESSION_HANDLE Session, _In_ const BYTE *Packet) {
            return getInstance()->WintunSendPacket(Session, Packet);
        }

    static bool
        isLoaded() {
            getInstance();
            return mInstance && mInstance->mLoaded;
        }

    static void unload();

private:
    WINTUN_CREATE_ADAPTER_FUNC              *WintunCreateAdapter = nullptr;
    WINTUN_CLOSE_ADAPTER_FUNC               *WintunCloseAdapter = nullptr;
    WINTUN_OPEN_ADAPTER_FUNC                *WintunOpenAdapter = nullptr;
    WINTUN_GET_ADAPTER_LUID_FUNC            *WintunGetAdapterLUID = nullptr;
    WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC  *WintunGetRunningDriverVersion = nullptr;
    WINTUN_DELETE_DRIVER_FUNC               *WintunDeleteDriver = nullptr;
    WINTUN_SET_LOGGER_FUNC                  *WintunSetLogger = nullptr;
    WINTUN_START_SESSION_FUNC               *WintunStartSession = nullptr;
    WINTUN_END_SESSION_FUNC                 *WintunEndSession = nullptr;
    WINTUN_GET_READ_WAIT_EVENT_FUNC         *WintunGetReadWaitEvent = nullptr;
    WINTUN_RECEIVE_PACKET_FUNC              *WintunReceivePacket = nullptr;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC      *WintunReleaseReceivePacket = nullptr;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC        *WintunAllocateSendPacket = nullptr;
    WINTUN_SEND_PACKET_FUNC                 *WintunSendPacket = nullptr;

    bool mLoaded = false;
    HMODULE mModule = 0;

    static
    WinTunLib* getInstance();

    WinTunLib();
/////////public:
    static WinTunLib *mInstance;
};

#endif // WINTUNLIB_H
