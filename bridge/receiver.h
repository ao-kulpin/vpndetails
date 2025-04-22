#ifndef RECEIVER_H
#define RECEIVER_H

#include <QThread>

class Receiver : QThread
{
    Q_OBJECT
//////public:
    Receiver();
    void run() override;
};

#endif // RECEIVER_H
