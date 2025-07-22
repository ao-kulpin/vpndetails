#ifndef INPUTREADER_H
#define INPUTREADER_H

#include <QObject>

#include "ringbuffer.h"
#include "ProtoBuilder.h"

// Reads an input stream of client/server and devides it into "peer requests" (VpnClientHello, ...)

const unsigned PeerRequestSize = 1024 * 20;

class InputReader : public QObject {
    Q_OBJECT

public:
    InputReader(unsigned _ringBufSize = 1024);
    bool takeInput(const u_char* _data, unsigned _len);

private:
    RingBuffer  mRingBuf;

signals:
    void peerRequest(const VpnHeader* _reqest);
};

#endif // INPUTREADER_H
