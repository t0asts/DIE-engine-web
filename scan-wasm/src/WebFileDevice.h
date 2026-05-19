
#pragma once

#include <QIODevice>
#include <cstdint>

class WebFileDevice : public QIODevice {
    Q_OBJECT

public:
    
    WebFileDevice(const uint8_t* data, qint64 size, QObject* parent = nullptr);
    ~WebFileDevice() override;

    bool isSequential() const override { return false; }
    qint64 size() const override { return m_size; }
    bool seek(qint64 pos) override;

protected:
    qint64 readData(char* dest, qint64 maxSize) override;
    qint64 writeData(const char* src, qint64 size) override;

private:
    const uint8_t* m_data;
    qint64 m_size;
};
