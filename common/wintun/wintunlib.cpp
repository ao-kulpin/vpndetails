#include <winsock2.h>
#include <Windows.h>

#include "wintunlib.h"

WinTunLib::WinTunLib() {
    mModule =
        LoadLibraryEx(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);

    if (!mModule)
        return;

#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(mModule, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket)) {
#undef X

    }



    mLoaded = true;
}

WinTunLib* WinTunLib::getInstance() {
    if (!mInstance)
        mInstance = new WinTunLib;

    return mInstance;
}

void WinTunLib::unload() {
    getInstance();
    if (mInstance) {
        FreeModule(mInstance->mModule);
        delete mInstance;
        mInstance = nullptr;
    }
}


