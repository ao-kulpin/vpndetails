#ifndef RINGBUFFER_H
#define RINGBUFFER_H

#include "vpntypes.h"

class RingBuffer
{
public:
    RingBuffer(unsigned _MaxBufSize = 1024);
    ~RingBuffer();

    unsigned            maxBufSize() const { return MaxBufSize; }
    unsigned            size() const;
    unsigned            freeSize() const;

    unsigned            getReadState() const        { return mReadPtr; }
    void                setReadState(unsigned rs)   { mReadPtr = rs; }
private:
    u_char*             mData = nullptr;
    const unsigned      MaxBufSize = 1024;
    unsigned            mReadPtr = 0;
    unsigned            mWritePtr = 0;
    bool                write(const u_char* _data, unsigned _len);
    bool                read(u_char* _data, unsigned _len);
};

#endif // RINGBUFFER_H
