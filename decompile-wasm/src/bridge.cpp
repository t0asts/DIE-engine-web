#include "WebArchitecture.h"
#include "WebLoadImage.h"
#include "libc_prototypes.h"

#include "address.hh"
#include "architecture.hh"
#include "database.hh"
#include "error.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include "libdecomp.hh"
#include "printlanguage.hh"
#include "sleigh_arch.hh"
#include "type.hh"
#include "varnode.hh"

#include <emscripten/emscripten.h>

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using ghidra::AddrSpace;
using ghidra::Address;
using ghidra::Datatype;
using ghidra::DocumentStorage;
using ghidra::Funcdata;
using ghidra::FuncCallSpecs;
using ghidra::FunctionSymbol;
using ghidra::LowlevelError;
using ghidra::PrototypePieces;
using ghidra::Range;
using ghidra::Scope;
using ghidra::SleighArchitecture;
using ghidra::Symbol;
using ghidra::TypeCode;
using ghidra::Varnode;
using ghidra::int4;
using ghidra::uint4;

bool g_initialized = false;

struct Handle {
    die_web::WebArchitecture *arch;
    bool libcImported = false;
    bool importsConverted = false;
    std::vector<uint64_t> noreturnAddrs;
    std::vector<std::pair<uint64_t, std::string>> imports;
    explicit Handle(die_web::WebArchitecture *a) : arch(a) {}
    ~Handle() { delete arch; }
};

bool isNoReturnName(const std::string &n) {
    static const char *const kNames[] = {
        "exit", "_exit", "_Exit", "quick_exit", "abort", "_abort",
        "__stack_chk_fail", "__assert_fail", "__chk_fail", "pthread_exit",
        "longjmp", "_longjmp", "siglongjmp", "__longjmp_chk",
        "ExitProcess", "ExitThread", "RtlExitUserProcess", "RtlExitUserThread",
        "_invoke_watson", "_invalid_parameter_noinfo_noreturn", "terminate",
    };
    for (const char *c : kNames) {
        if (n == c) return true;
    }
    return false;
}

void convertImportsToFuncPtrs(Handle *h) {
    auto *arch = h->arch;
    try {
        AddrSpace *space = arch->getDefaultCodeSpace();
        Scope *scope = arch->symboltab->getGlobalScope();
        auto *types = arch->types;
        const int4 ps = static_cast<int4>(space->getAddrSize());
        const uint4 ws = space->getWordSize();
        for (const auto &imp : h->imports) {
            try {
                const Address a(space, imp.first);
                Funcdata *fd = scope->findFunction(a);
                if (fd == nullptr) continue;
                if (!fd->getFuncProto().isInputLocked()) continue;
                PrototypePieces pieces;
                fd->getFuncProto().getPieces(pieces);
                TypeCode *tc = types->getTypeCode(pieces);
                Datatype *fptr = types->getTypePointer(ps, tc, ws);
                Symbol *sym = fd->getSymbol();
                scope->removeSymbol(sym);
                scope->addSymbol(imp.second, fptr, a, Address());
            } catch (const std::exception &) {
            }
        }
    } catch (const std::exception &) {
    }
}

char *dupCString(const std::string &src) {
    char *out = static_cast<char *>(std::malloc(src.size() + 1));
    if (!out) return nullptr;
    std::memcpy(out, src.data(), src.size());
    out[src.size()] = '\0';
    return out;
}

std::string toHex(uint64_t v) {
    std::ostringstream oss;
    oss << std::hex << v;
    return oss.str();
}

std::string jsonEscape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

void ensureInitialized() {
    if (g_initialized) return;
    ghidra::startDecompilerLibrary(std::vector<std::string>{});
    g_initialized = true;
}

void importLibcPrototypes(die_web::WebArchitecture *arch) {
    const std::string buf(die_web::LIBC_PROTOTYPES);
    std::size_t pos = 0;
    while (pos < buf.size()) {
        const std::size_t semi = buf.find(';', pos);
        if (semi == std::string::npos) break;
        std::string decl = buf.substr(pos, semi - pos + 1);
        pos = semi + 1;
        bool hasContent = false;
        for (char c : decl) {
            if (!std::isspace(static_cast<unsigned char>(c))) { hasContent = true; break; }
        }
        if (!hasContent) continue;
        try {
            std::istringstream is(decl);
            ghidra::parse_C(arch, is);
        } catch (const LowlevelError &) {
        } catch (const std::exception &) {
        }
    }
}

Handle *asHandle(void *p) { return static_cast<Handle *>(p); }

}

extern "C" {

EMSCRIPTEN_KEEPALIVE
int decomp_init(const char *specRoot) {
    try {
        ensureInitialized();
        if (specRoot && *specRoot) SleighArchitecture::specpaths.addDir2Path(specRoot);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "decomp_init: " << e.what() << std::endl;
        return 1;
    }
}

EMSCRIPTEN_KEEPALIVE
int decomp_add_spec_dir(const char *dir) {
    try {
        ensureInitialized();
        if (!dir || !*dir) return -1;
        SleighArchitecture::specpaths.addDir2Path(dir);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "decomp_add_spec_dir: " << e.what() << std::endl;
        return -1;
    }
}

EMSCRIPTEN_KEEPALIVE
void *decomp_create(const char *languageId) {
    if (!languageId || !*languageId) return nullptr;
    die_web::WebArchitecture *arch = nullptr;
    try {
        ensureInitialized();
        arch = new die_web::WebArchitecture(languageId, &std::cerr);
        DocumentStorage store;
        arch->init(store);
    } catch (const LowlevelError &e) {
        std::cerr << "decomp_create: " << e.explain << std::endl;
        delete arch;
        return nullptr;
    } catch (const std::exception &e) {
        std::cerr << "decomp_create: " << e.what() << std::endl;
        delete arch;
        return nullptr;
    }
    return new Handle(arch);
}

EMSCRIPTEN_KEEPALIVE
int decomp_add_region(void *handle, uint64_t addr, const uint8_t *bytes, uint32_t size) {
    if (!handle || !bytes || size == 0) return -1;
    try {
        asHandle(handle)->arch->addRegion(addr, bytes, size);
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "decomp_add_region: " << e.what() << std::endl;
        return -1;
    }
}

EMSCRIPTEN_KEEPALIVE
int decomp_add_symbol(void *handle, uint64_t addr, const char *name) {
    if (!handle || !name || !*name) return -1;
    try {
        auto *h = asHandle(handle);
        if (isNoReturnName(name)) h->noreturnAddrs.push_back(addr);
        auto *arch = h->arch;
        AddrSpace *space = arch->getDefaultCodeSpace();
        Scope *scope = arch->symboltab->getGlobalScope();
        const Address a(space, addr);
        if (scope->findFunction(a) != nullptr) return 0;
        scope->addFunction(a, std::string(name));
        return 0;
    } catch (const std::exception &) {
        return -1;
    }
}

EMSCRIPTEN_KEEPALIVE
int decomp_add_import(void *handle, uint64_t addr, const char *name) {
    if (!handle || !name || !*name) return -1;
    try {
        auto *h = asHandle(handle);
        auto *arch = h->arch;
        AddrSpace *space = arch->getDefaultCodeSpace();
        Scope *scope = arch->symboltab->getGlobalScope();
        const Address a(space, addr);
        if (scope->findFunction(a) == nullptr)
            scope->addFunction(a, std::string(name));
        h->imports.push_back({addr, std::string(name)});
        return 0;
    } catch (const std::exception &) {
        return -1;
    }
}

EMSCRIPTEN_KEEPALIVE
int decomp_add_string(void *handle, uint64_t addr, uint64_t length) {
    if (!handle || length == 0) return -1;
    try {
        auto *arch = asHandle(handle)->arch;
        AddrSpace *space = arch->getDefaultCodeSpace();
        Scope *scope = arch->symboltab->getGlobalScope();
        const Address a(space, addr);
        if (scope->queryContainer(a, 1, Address()) != nullptr) return 0;
        Datatype *charType = arch->types->getTypeChar(1);
        const int4 len = static_cast<int4>(length < 4096 ? length : 4096);
        Datatype *arrType = arch->types->getTypeArray(len, charType);
        std::ostringstream nm;
        nm << "s_" << std::hex << addr;
        scope->addSymbol(nm.str(), arrType, a, Address());
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "decomp_add_string: " << e.what() << std::endl;
        return -1;
    }
}

EMSCRIPTEN_KEEPALIVE
int decomp_add_readonly(void *handle, uint64_t addr, uint64_t size) {
    if (!handle || size == 0) return -1;
    try {
        auto *arch = asHandle(handle)->arch;
        AddrSpace *space = arch->getDefaultCodeSpace();
        arch->symboltab->setPropertyRange(Varnode::readonly,
                                          Range(space, addr, addr + size - 1));
        return 0;
    } catch (const std::exception &) {
        return -1;
    }
}

EMSCRIPTEN_KEEPALIVE
char *decomp_decompile(void *handle, uint64_t addr, const char *name) {
    if (!handle) return nullptr;
    auto *h = asHandle(handle);

    if (!h->libcImported) {
        importLibcPrototypes(h->arch);
        h->libcImported = true;
    }
    if (!h->importsConverted) {
        convertImportsToFuncPtrs(h);
        h->importsConverted = true;
    }

    auto asComment = [](const std::string &msg) -> char * {
        return dupCString("/* decompile error: " + msg + " */\n");
    };

    try {
        auto *arch = h->arch;
        AddrSpace *space = arch->getDefaultCodeSpace();
        const Address a(space, addr);
        Scope *scope = arch->symboltab->getGlobalScope();

        for (uint64_t na : h->noreturnAddrs) {
            Funcdata *nfd = scope->findFunction(Address(space, na));
            if (nfd != nullptr) nfd->getFuncProto().setNoReturn(true);
        }

        Funcdata *fd = scope->findFunction(a);
        if (fd == nullptr) {
            std::string nm = (name && *name) ? std::string(name) : "";
            if (nm.empty()) {
                std::ostringstream oss;
                oss << "FUN_" << std::hex << addr;
                nm = oss.str();
            }
            FunctionSymbol *sym = scope->addFunction(a, nm);
            fd = sym->getFunction();
        } else {
            arch->clearAnalysis(fd);
        }

        auto *action = arch->allacts.getCurrent();
        action->reset(*fd);
        const int4 res = action->perform(*fd);
        if (res < 0) return asComment("decompilation interrupted");

        std::ostringstream oss;
        arch->print->setOutputStream(&oss);
        arch->print->docFunction(fd);
        const std::string code = oss.str();
        return dupCString(code);
    } catch (const LowlevelError &e) {
        return asComment(e.explain);
    } catch (const std::exception &e) {
        return asComment(e.what());
    }
}

EMSCRIPTEN_KEEPALIVE
char *decomp_call_targets(void *handle, uint64_t addr) {
    if (!handle) return dupCString("[]");
    try {
        auto *arch = asHandle(handle)->arch;
        AddrSpace *code = arch->getDefaultCodeSpace();
        Scope *scope = arch->symboltab->getGlobalScope();
        const Address a(code, addr);
        Funcdata *fd = scope->findFunction(a);
        if (fd == nullptr || !fd->isProcStarted()) return dupCString("[]");

        std::string out = "[";
        bool first = true;
        std::vector<uint64_t> seen;
        const int4 n = fd->numCalls();
        for (int4 i = 0; i < n; ++i) {
            FuncCallSpecs *cs = fd->getCallSpecs(i);
            if (cs == nullptr) continue;
            const Address &t = cs->getEntryAddress();
            if (t.isInvalid() || t.getSpace() != code) continue;
            const uint64_t ta = static_cast<uint64_t>(t.getOffset());
            if (ta == 0) continue;
            bool dup = false;
            for (uint64_t s : seen) if (s == ta) { dup = true; break; }
            if (dup) continue;
            seen.push_back(ta);

            if (!first) out += ",";
            first = false;
            out += "{\"addr\":";
            out += std::to_string(ta);
            const std::string nm = cs->getName();
            if (!nm.empty()) { out += ",\"name\":\""; out += jsonEscape(nm); out += "\""; }
            out += "}";
        }
        out += "]";
        return dupCString(out);
    } catch (const std::exception &e) {
        std::cerr << "decomp_call_targets: " << e.what() << std::endl;
        return dupCString("[]");
    }
}

EMSCRIPTEN_KEEPALIVE
void decomp_free_string(char *s) { std::free(s); }

EMSCRIPTEN_KEEPALIVE
void decomp_destroy(void *handle) {
    if (handle) delete asHandle(handle);
}

}
