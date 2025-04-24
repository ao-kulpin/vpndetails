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

class RealSender : public QThread
{
    Q_OBJECT
    void run() override;

public:
    bool openAdapter();
};

#endif // RECEIVER_H
