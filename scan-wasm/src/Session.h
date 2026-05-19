
#pragma once

#include <QByteArray>
#include <memory>
#include <vector>

#include "binary_script.h"   

class WebFileDevice;

namespace die_web {

class Session {
public:
    Session();
    ~Session();

    bool open(const uint8_t* bytes, size_t size, const char* optionsJson = nullptr);

    Binary_Script* script() const { return m_script.get(); }
    XBinary* binary() const { return m_binary.get(); }

    const std::string& jsClass() const { return m_jsClass; }

private:
    std::vector<uint8_t> m_bytesOwned;       
    std::unique_ptr<WebFileDevice> m_device;
    std::unique_ptr<XBinary>       m_binary;
    std::unique_ptr<Binary_Script> m_script;
    std::string                    m_jsClass;
    
    Binary_Script::OPTIONS         m_options{};
    XBinary::PDSTRUCT              m_pd{};
};

}  
