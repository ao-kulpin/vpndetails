#ifndef HANDLERS_H
#define HANDLERS_H

#include <QThread>

class ClientHandler : public QThread
{
    Q_OBJECT
public:
    ClientHandler(qintptr socketDescriptor, QObject *parent = nullptr);

    void run() override;
private:
    qintptr mSocketDescriptor;
};

#endif // HANDLERS_H
