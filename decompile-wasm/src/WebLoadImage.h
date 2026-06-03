#ifndef DIE_WEB_WEB_LOADIMAGE_H
#define DIE_WEB_WEB_LOADIMAGE_H

#include "loadimage.hh"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace die_web {

class WebLoadImage : public ghidra::LoadImage {
    struct Region {
        uint64_t base;
        std::vector<uint8_t> bytes;
    };
    std::vector<Region> regions;

public:
    WebLoadImage();

    void addRegion(uint64_t addr, const uint8_t *bytes, std::size_t size);

    void loadFill(ghidra::uint1 *ptr, ghidra::int4 size,
                  const ghidra::Address &addr) override;
    std::string getArchType(void) const override;
    void adjustVma(long adjust) override;
};

}

#endif
