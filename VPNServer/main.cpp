#include <QCoreApplication>

#include "ServerData.h"

ServerData cdata; // common data of the application

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    return a.exec();
}
