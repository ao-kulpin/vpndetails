#ifndef RECEIVER_H
#define RECEIVER_H

#include <QThread>

class VirtReceiver : public QThread
{
    Q_OBJECT
    void run() override;

public:
    VirtReceiver();
};

#endif // RECEIVER_H
