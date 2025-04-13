#include <QCoreApplication>
#include <iostream>
#include <QDebug>
#include <stdio.h>

#include "wintunlib.h"

#include "killer.h"

WinTunLib* WinTunLib::mInstance = nullptr;

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    if(WinTunLib::isLoaded())
        printf("wintun.dll is loaded\n");
    else {
        printf("Can't load wintun.dll\n");
        return 1;
    }

    Killer wtlk ( [] {
        WinTunLib::unload();
        printf("wintun.dll is unloaded\n");
    });

    printf("Hello\n");
    ///////// qDebug() << "Hello\n";

    a.exit();
}
