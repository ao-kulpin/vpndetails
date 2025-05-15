#ifndef HANDLERS_H
#define HANDLERS_H

#include <memory>

#include <QTcpSocket>

class VPNSocket : public QObject {
    Q_OBJECT
public:
    VPNSocket(QObject *parent = nullptr);

private slots:
    void onConnected();
    void onReadyRead();

private:
    std::unique_ptr<QTcpSocket> mTcpSocket;
};


#endif // HANDLERS_H
