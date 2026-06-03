#include "WebFileDevice.h"

#include <algorithm>
#include <cstring>

WebFileDevice::WebFileDevice(const uint8_t* data, qint64 size, QObject* parent)
    : QIODevice(parent), m_data(data), m_size(size) {
    open(QIODevice::ReadOnly);
}

WebFileDevice::~WebFileDevice() = default;

bool WebFileDevice::seek(qint64 pos) {
    if (pos < 0 || pos > m_size) return false;
    return QIODevice::seek(pos);
}

qint64 WebFileDevice::readData(char* dest, qint64 maxSize) {
    const qint64 cur = pos();
    if (cur >= m_size) return 0;
    const qint64 n = std::min<qint64>(maxSize, m_size - cur);
    std::memcpy(dest, m_data + cur, static_cast<size_t>(n));
    return n;
}

qint64 WebFileDevice::writeData(const char* , qint64 ) {
    return -1;
}
