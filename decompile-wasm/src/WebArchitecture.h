#ifndef DIE_WEB_WEB_ARCHITECTURE_H
#define DIE_WEB_WEB_ARCHITECTURE_H

#include "sleigh_arch.hh"

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>

namespace die_web {

class WebLoadImage;

class WebArchitecture : public ghidra::SleighArchitecture {
    WebLoadImage *image;

public:
    WebArchitecture(const std::string &languageId, std::ostream *errstream);

    void addRegion(uint64_t addr, const uint8_t *bytes, std::size_t size);

protected:
    void buildLoader(ghidra::DocumentStorage &store) override;
    void buildCoreTypes(ghidra::DocumentStorage &store) override;
    void buildAction(ghidra::DocumentStorage &store) override;
    void resolveArchitecture(void) override;
    void postSpecFile(void) override;
};

}

#endif
