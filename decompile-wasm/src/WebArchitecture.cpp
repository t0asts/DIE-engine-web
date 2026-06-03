#include "WebArchitecture.h"
#include "WebLoadImage.h"

#include "architecture.hh"
#include "coreaction.hh"
#include "type.hh"

namespace die_web {

using ghidra::Architecture;
using ghidra::DocumentStorage;
using ghidra::SleighArchitecture;
using ghidra::TYPE_BOOL;
using ghidra::TYPE_CODE;
using ghidra::TYPE_FLOAT;
using ghidra::TYPE_INT;
using ghidra::TYPE_UINT;
using ghidra::TYPE_UNKNOWN;
using ghidra::TYPE_VOID;

WebArchitecture::WebArchitecture(const std::string &languageId, std::ostream *errstream)
    : SleighArchitecture("dieweb", languageId, errstream),
      image(new WebLoadImage()) {
    collectSpecFiles(*errorstream);
}

void WebArchitecture::addRegion(uint64_t addr, const uint8_t *bytes, std::size_t size) {
    image->addRegion(addr, bytes, size);
}

void WebArchitecture::buildLoader(DocumentStorage & /*store*/) {
    loader = image;
}

void WebArchitecture::buildCoreTypes(DocumentStorage & /*store*/) {
    types->setCoreType("void", 1, TYPE_VOID, false);

    types->setCoreType("bool", 1, TYPE_BOOL, false);

    types->setCoreType("uint1", 1, TYPE_UINT, false);
    types->setCoreType("uint2", 2, TYPE_UINT, false);
    types->setCoreType("uint4", 4, TYPE_UINT, false);
    types->setCoreType("uint8", 8, TYPE_UINT, false);
    types->setCoreType("int1", 1, TYPE_INT, false);
    types->setCoreType("int2", 2, TYPE_INT, false);
    types->setCoreType("int4", 4, TYPE_INT, false);
    types->setCoreType("int8", 8, TYPE_INT, false);

    types->setCoreType("float4", 4, TYPE_FLOAT, false);
    types->setCoreType("float8", 8, TYPE_FLOAT, false);
    types->setCoreType("float10", 10, TYPE_FLOAT, false);

    types->setCoreType("undefined", 1, TYPE_UNKNOWN, false);
    types->setCoreType("undefined1", 1, TYPE_UNKNOWN, false);
    types->setCoreType("undefined2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("undefined4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("undefined8", 8, TYPE_UNKNOWN, false);

    types->setCoreType("code", 1, TYPE_CODE, false);

    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("wchar2", 2, TYPE_INT, true);
    types->setCoreType("wchar4", 4, TYPE_INT, true);

    types->cacheCoreTypes();
}

void WebArchitecture::buildAction(DocumentStorage &store) {
    parseExtraRules(store);
    allacts.universalAction(this);
    allacts.resetDefaults();
}

void WebArchitecture::resolveArchitecture(void) {
    archid = getTarget();
    SleighArchitecture::resolveArchitecture();
}

void WebArchitecture::postSpecFile(void) {
    Architecture::postSpecFile();
}

}
