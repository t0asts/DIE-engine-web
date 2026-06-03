#include "WebLoadImage.h"

#include "error.hh"

#include <cstring>
#include <sstream>

namespace die_web {

using ghidra::Address;
using ghidra::DataUnavailError;
using ghidra::int4;
using ghidra::uint1;

WebLoadImage::WebLoadImage() : ghidra::LoadImage("dieweb") {}

void WebLoadImage::addRegion(uint64_t addr, const uint8_t *bytes, std::size_t size) {
    regions.push_back({addr, std::vector<uint8_t>(bytes, bytes + size)});
}

void WebLoadImage::loadFill(uint1 *ptr, int4 size, const Address &addr) {
    if (ptr == nullptr || size <= 0) return;

    const uint64_t start = addr.getOffset();
    const uint64_t end = start + static_cast<uint64_t>(size);

    std::memset(ptr, 0, static_cast<std::size_t>(size));

    bool filledAny = false;
    for (const auto &r : regions) {
        const uint64_t rStart = r.base;
        const uint64_t rEnd = r.base + r.bytes.size();
        const uint64_t lo = start > rStart ? start : rStart;
        const uint64_t hi = end < rEnd ? end : rEnd;
        if (lo < hi) {
            std::memcpy(ptr + (lo - start),
                        r.bytes.data() + (lo - rStart),
                        static_cast<std::size_t>(hi - lo));
            filledAny = true;
        }
    }

    if (!filledAny) {
        std::ostringstream oss;
        oss << "no mapped bytes at 0x" << std::hex << start;
        throw DataUnavailError(oss.str());
    }
}

std::string WebLoadImage::getArchType(void) const { return "dieweb"; }

void WebLoadImage::adjustVma(long /*adjust*/) {
    throw ghidra::LowlevelError("dieweb load image does not support VMA adjustment");
}

}
