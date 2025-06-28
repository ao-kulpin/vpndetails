#include <stdio.h>

#include <algorithm>

#include "ringbuffer.h"

RingBuffer::RingBuffer(unsigned _MaxBufSize) : MaxBufSize (_MaxBufSize) {
    mData = new u_char[MaxBufSize];
    mReadPtr = mWritePtr = 0;
}

RingBuffer::~RingBuffer() {
    if (mData) {
        delete mData;
        mData = nullptr;
    }
}

unsigned RingBuffer::size() const {
    return (mWritePtr + MaxBufSize - mReadPtr) % MaxBufSize;
}
unsigned RingBuffer::freeSize() const {
    return MaxBufSize - size();
}

bool RingBuffer::write(const u_char* _data, unsigned _len) {
    if (_len > freeSize()) {
        printf("*** Ringbuffer is overflowed\n");
        return false;
    }

    const unsigned part1Len = std::min(_len, MaxBufSize - mWritePtr);

    memcpy(mData + mWritePtr, _data, part1Len);

    if (part1Len == _len)
        mWritePtr += _len;
    else {
        const unsigned part2Len = _len - part1Len;
        memcpy(mData, _data + part1Len, part2Len);
        mWritePtr = part2Len;
    }

    return true;

}
bool RingBuffer::read(u_char* _data, unsigned _len) {
    if (_len < size())
        return false;

    const unsigned part1Len = std::min(_len, MaxBufSize - mReadPtr);

    memcpy(_data, mData + mReadPtr, part1Len);

    if (part1Len == _len)
        mReadPtr += _len;
    else {
        const unsigned part2Len = _len - part1Len;
        memcpy(_data + part1Len, mData, part2Len);
        mReadPtr = part2Len;
    }

    return true;
}



