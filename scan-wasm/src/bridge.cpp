
#include <emscripten.h>

#include <QAbstractItemModel>
#include <QBuffer>
#include <QByteArray>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QModelIndex>
#include <QString>
#include <QStringList>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "Session.h"

#include "binary_script.h"
#include "xbinary.h"

#include "xfileinfo.h"
#include "xfileinfomodel.h"
#include "xdisasmcore.h"
#include "xdisasmabstract.h"

#include "xpe.h"
#include "xelf.h"
#include "xelf_def.h"
#include "xmach.h"
#include "xmach_def.h"

namespace {

struct DieHandle {
    QString signaturesRoot;
};

DieHandle* asHandle(void* p) { return static_cast<DieHandle*>(p); }
die_web::Session* asSession(void* p) { return static_cast<die_web::Session*>(p); }

char* dupCString(const QByteArray& src) {
    char* out = static_cast<char*>(std::malloc(static_cast<size_t>(src.size()) + 1));
    if (!out) return nullptr;
    std::memcpy(out, src.constData(), static_cast<size_t>(src.size()));
    out[src.size()] = '\0';
    return out;
}

char* dupCString(const std::string& src) {
    char* out = static_cast<char*>(std::malloc(src.size() + 1));
    if (!out) return nullptr;
    std::memcpy(out, src.data(), src.size());
    out[src.size()] = '\0';
    return out;
}

QJsonArray fileInfoChildrenToJson(XFileInfoItem* parent) {
    QJsonArray arr;
    if (!parent) return arr;
    const int n = parent->childCount();
    for (int i = 0; i < n; ++i) {
        XFileInfoItem* c = parent->child(i);
        if (!c) continue;
        QJsonObject node;
        node["name"] = c->getName();
        const QString v = c->getValue().toString();
        if (!v.isEmpty()) node["value"] = v;
        const QJsonArray kids = fileInfoChildrenToJson(c);
        if (!kids.isEmpty()) node["children"] = kids;
        arr.append(node);
    }
    return arr;
}

QJsonObject fileInfoItemToJson(XFileInfoItem* item) {
    QJsonObject node;
    if (!item) return node;
    node["name"] = item->getName();
    const QString v = item->getValue().toString();
    if (!v.isEmpty()) node["value"] = v;
    const QJsonArray kids = fileInfoChildrenToJson(item);
    if (!kids.isEmpty()) node["children"] = kids;
    return node;
}

QString sHex(qint64 n) { return n < 0 ? QStringLiteral("-") : QStringLiteral("0x") + QString::number(static_cast<qulonglong>(n), 16); }
QString sHexU(quint64 n) { return QStringLiteral("0x") + QString::number(n, 16); }
QJsonObject jLeaf(const QString& name, const QString& value) {
    QJsonObject o; o["name"] = name; if (!value.isEmpty()) o["value"] = value; return o;
}
QJsonObject jGroup(const QString& name, const QString& value, const QJsonArray& children) {
    QJsonObject o; o["name"] = name; if (!value.isEmpty()) o["value"] = value; if (!children.isEmpty()) o["children"] = children; return o;
}

void appendPeStruct(XPE* pe, QJsonArray& top) {
    XBinary::PDSTRUCT pd = XBinary::createPdStruct();

    if (pe->isImportPresent()) {
        const QList<XPE::IMPORT_HEADER> imps = pe->getImports(&pd);
        QJsonArray dlls; int totalFuncs = 0;
        for (const auto& ih : imps) {
            if (dlls.size() >= 2000) break;
            QJsonArray funcs;
            for (const auto& ip : ih.listPositions) {
                if (funcs.size() >= 5000 || totalFuncs >= 60000) break;
                QString name = ip.sFunction;
                if (name.isEmpty()) name = (ip.nOrdinal >= 0) ? QStringLiteral("#") + QString::number(ip.nOrdinal) + QStringLiteral(" (by ordinal)") : QStringLiteral("(unnamed)");
                QStringList m;
                if (!ip.sFunction.isEmpty() && ip.nHint) m << QStringLiteral("hint ") + sHexU(ip.nHint);
                if (ip.nThunkRVA > 0) m << QStringLiteral("thunk RVA ") + sHex(ip.nThunkRVA);
                funcs.append(jLeaf(name, m.join(QStringLiteral(" · "))));
                ++totalFuncs;
            }
            dlls.append(jGroup(ih.sName.isEmpty() ? QStringLiteral("(unnamed)") : ih.sName,
                               QString::number(ih.listPositions.size()) + QStringLiteral(" function(s)"), funcs));
        }
        if (!dlls.isEmpty()) top.append(jGroup(QStringLiteral("Imports"), QString::number(imps.size()) + QStringLiteral(" DLL(s)"), dlls));
    }

    if (pe->isTLSPresent()) {
        const XPE::TLS_HEADER tls = pe->getTLSHeader();
        QJsonArray ch;
        ch.append(jLeaf(QStringLiteral("StartAddressOfRawData"), sHexU(tls.StartAddressOfRawData)));
        ch.append(jLeaf(QStringLiteral("EndAddressOfRawData"),   sHexU(tls.EndAddressOfRawData)));
        ch.append(jLeaf(QStringLiteral("AddressOfIndex"),        sHexU(tls.AddressOfIndex)));
        ch.append(jLeaf(QStringLiteral("AddressOfCallBacks"),    sHexU(tls.AddressOfCallBacks)));
        ch.append(jLeaf(QStringLiteral("SizeOfZeroFill"),        QString::number(tls.SizeOfZeroFill)));
        ch.append(jLeaf(QStringLiteral("Characteristics"),       sHexU(tls.Characteristics)));
        top.append(jGroup(QStringLiteral("TLS"), QString(), ch));
    }

    if (pe->isLoadConfigPresent()) {
        QJsonArray ch;
        ch.append(jLeaf(QStringLiteral("Size"),                          sHexU(pe->getLoadConfig_Size())));
        ch.append(jLeaf(QStringLiteral("TimeDateStamp"),                 sHexU(pe->getLoadConfig_TimeDateStamp())));
        ch.append(jLeaf(QStringLiteral("Version"),                       QString::number(pe->getLoadConfig_MajorVersion()) + QStringLiteral(".") + QString::number(pe->getLoadConfig_MinorVersion())));
        ch.append(jLeaf(QStringLiteral("GlobalFlagsClear"),              sHexU(pe->getLoadConfig_GlobalFlagsClear())));
        ch.append(jLeaf(QStringLiteral("GlobalFlagsSet"),                sHexU(pe->getLoadConfig_GlobalFlagsSet())));
        ch.append(jLeaf(QStringLiteral("CriticalSectionDefaultTimeout"), QString::number(pe->getLoadConfig_CriticalSectionDefaultTimeout())));
        ch.append(jLeaf(QStringLiteral("SecurityCookie"),                sHexU(pe->getLoadConfig_SecurityCookie())));
        top.append(jGroup(QStringLiteral("Load config"), QString(), ch));
    }

    if (pe->isRelocsPresent()) {
        const QList<XPE::RELOCS_HEADER> rh = pe->getRelocsHeaders(&pd);
        if (!rh.isEmpty()) {
            QJsonArray ch; qint64 total = 0;
            for (const auto& b : rh) {
                total += b.nCount;
                if (ch.size() < 256) ch.append(jLeaf(QStringLiteral("block @ ") + sHexU(b.baseRelocation.VirtualAddress),
                                                     QString::number(b.nCount) + QStringLiteral(" entries")));
            }
            top.append(jGroup(QStringLiteral("Relocations"),
                              QString::number(rh.size()) + QStringLiteral(" block(s), ") + QString::number(total) + QStringLiteral(" entries"), ch));
        }
    }
}

void appendElfStruct(XELF* elf, QJsonArray& top) {
    const QList<XELF::TAG_STRUCT> tags = elf->getTagStructs();
    if (!tags.isEmpty()) {
        QJsonArray ch;
        const QList<QString> libs = elf->getLibraries();
        if (!libs.isEmpty()) {
            QJsonArray la; for (const QString& l : libs) la.append(jLeaf(l, QString()));
            ch.append(jGroup(QStringLiteral("Needed libraries"), QString::number(libs.size()), la));
        }
        const QMap<quint64, QString> tagNames = XELF::getDynamicTags(elf->getArch());
        QJsonArray ta; int n = 0;
        for (const auto& t : tags) {
            if (n++ >= 500) break;
            const QString tn = tagNames.value(static_cast<quint64>(t.nTag), QString());
            ta.append(jLeaf((tn.isEmpty() ? QString() : tn + QStringLiteral(" ")) + QStringLiteral("(") + sHex(t.nTag) + QStringLiteral(")"), sHex(t.nValue)));
        }
        ch.append(jGroup(QStringLiteral("Tags"), QString::number(tags.size()), ta));
        top.append(jGroup(QStringLiteral("Dynamic section"), QString(), ch));
    }
    const QList<XELF::NOTE> notes = elf->getNotes();
    if (!notes.isEmpty()) {
        QJsonArray ch;
        for (const auto& nt : notes)
            ch.append(jLeaf((nt.sName.isEmpty() ? QStringLiteral("(unnamed)") : nt.sName) + QStringLiteral(" (type ") + sHexU(nt.nType) + QStringLiteral(")"),
                            QString::number(nt.nDataSize) + QStringLiteral(" bytes @ ") + sHex(nt.nDataOffset)));
        top.append(jGroup(QStringLiteral("Notes"), QString::number(notes.size()), ch));
    }
}

const char* machCmdName(quint32 id) {
    switch (id & 0x7fffffffu) {
        case 0x01: return "LC_SEGMENT";          case 0x02: return "LC_SYMTAB";
        case 0x03: return "LC_SYMSEG";           case 0x04: return "LC_THREAD";
        case 0x05: return "LC_UNIXTHREAD";       case 0x0b: return "LC_DYSYMTAB";
        case 0x0c: return "LC_LOAD_DYLIB";       case 0x0d: return "LC_ID_DYLIB";
        case 0x0e: return "LC_LOAD_DYLINKER";    case 0x0f: return "LC_ID_DYLINKER";
        case 0x18: return "LC_LOAD_WEAK_DYLIB";  case 0x19: return "LC_SEGMENT_64";
        case 0x1b: return "LC_UUID";             case 0x1c: return "LC_RPATH";
        case 0x1d: return "LC_CODE_SIGNATURE";   case 0x1e: return "LC_SEGMENT_SPLIT_INFO";
        case 0x21: return "LC_ENCRYPTION_INFO";  case 0x22: return "LC_DYLD_INFO";
        case 0x24: return "LC_VERSION_MIN_MACOSX"; case 0x25: return "LC_VERSION_MIN_IPHONEOS";
        case 0x26: return "LC_FUNCTION_STARTS";  case 0x28: return "LC_MAIN";
        case 0x29: return "LC_DATA_IN_CODE";     case 0x2a: return "LC_SOURCE_VERSION";
        case 0x2c: return "LC_ENCRYPTION_INFO_64"; case 0x32: return "LC_BUILD_VERSION";
        default: return "";
    }
}
void appendMachStruct(XMACH* mach, QJsonArray& top) {
    const QList<XMACH::COMMAND_RECORD> cmds = mach->getCommandRecords();
    if (cmds.isEmpty()) return;
    QJsonArray ch; int n = 0;
    for (const auto& c : cmds) {
        if (n++ >= 1000) break;
        const char* nm = machCmdName(c.nId);
        const QString label = (*nm ? QString::fromLatin1(nm) : QStringLiteral("LC ") + sHexU(c.nId)) + QStringLiteral(" (@ ") + sHex(c.nStructOffset) + QStringLiteral(")");
        ch.append(jLeaf(label, QString::number(c.nSize) + QStringLiteral(" bytes")));
    }
    top.append(jGroup(QStringLiteral("Load commands"), QString::number(cmds.size()), ch));
}

}  

extern "C" char* die_dispatch_invoke(die_web::Session* session, int methodId,
                                     const char* argsJson);

extern "C" {

EMSCRIPTEN_KEEPALIVE
void* die_create(void) {
    return new DieHandle();
}

EMSCRIPTEN_KEEPALIVE
void die_destroy(void* handle) {
    delete asHandle(handle);
}

EMSCRIPTEN_KEEPALIVE
int die_set_signatures_root(void* handle, const char* path) {
    auto* h = asHandle(handle);
    if (!h || !path) return -1;
    h->signaturesRoot = QString::fromUtf8(path);
    return 0;
}

EMSCRIPTEN_KEEPALIVE
void die_free_string(char* s) {
    std::free(s);
}

EMSCRIPTEN_KEEPALIVE
void* die_open_session(void* handle, const uint8_t* bytes, size_t size, const char* optionsJson) {
    auto* h = asHandle(handle);
    if (!h || !bytes || size == 0) return nullptr;
    auto session = std::make_unique<die_web::Session>();
    if (!session->open(bytes, size, optionsJson)) return nullptr;   
    return session.release();
}

EMSCRIPTEN_KEEPALIVE
void die_close_session(void* session) {
    delete asSession(session);
}

EMSCRIPTEN_KEEPALIVE
char* die_session_jsclass(void* session) {
    auto* s = asSession(session);
    if (!s) return nullptr;
    return dupCString(s->jsClass());
}

EMSCRIPTEN_KEEPALIVE
char* die_invoke(void* session, int methodId, const char* argsJson) {
    auto* s = asSession(session);
    if (!s) return nullptr;
    return die_dispatch_invoke(s, methodId, argsJson);
}

EMSCRIPTEN_KEEPALIVE
char* die_get_memory_map(void* session) {
    auto* s = asSession(session);
    if (!s || !s->binary()) return nullptr;

    XBinary::PDSTRUCT pd = {};
    XBinary::_MEMORY_MAP mm = s->binary()->getMemoryMap(XBinary::MAPMODE_UNKNOWN, &pd);

    QJsonObject out;
    out["moduleAddress"] = static_cast<double>(mm.nModuleAddress);
    out["imageSize"]     = static_cast<double>(mm.nImageSize);
    out["binarySize"]    = static_cast<double>(mm.nBinarySize);
    out["entryPoint"]    = static_cast<double>(mm.nEntryPointAddress);
    out["fileType"]      = XBinary::fileTypeIdToString(mm.fileType);
    out["arch"]          = mm.sArch;
    out["mode"]          = XBinary::modeIdToString(mm.mode);
    out["endian"]        = (mm.endian == XBinary::ENDIAN_BIG) ? "big" : "little";

    QJsonArray records;
    for (const auto& r : mm.listRecords) {
        QJsonObject rec;
        rec["name"]        = r.sName;
        rec["offset"]      = static_cast<double>(r.nOffset);
        rec["address"]     = static_cast<double>(r.nAddress);
        rec["size"]        = static_cast<double>(r.nSize);
        rec["index"]       = r.nIndex;
        rec["isVirtual"]   = r.bIsVirtual;
        rec["isInvisible"] = r.bIsInvisible;
        rec["filePart"]    = static_cast<int>(r.filePart);
        records.append(rec);
    }
    out["records"] = records;

    return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
}

}  

#include "xcppfilt.h"

extern "C" {

EMSCRIPTEN_KEEPALIVE
char* die_demangle(const char* name) {
    if (!name || !*name) return nullptr;
    QString in = QString::fromUtf8(name);

    QString d;
    d = XCppfilt::demangleGnuV3(in);     if (!d.isEmpty() && d != in) goto done;
    d = XCppfilt::demangleRust(in);      if (!d.isEmpty() && d != in) goto done;
    d = XCppfilt::demangleDLANG(in);     if (!d.isEmpty() && d != in) goto done;
    d = XCppfilt::demangleJavaV3(in);    if (!d.isEmpty() && d != in) goto done;
    d = XCppfilt::demangleGNAT(in);      if (!d.isEmpty() && d != in) goto done;
    return nullptr;
done:
    return dupCString(d.toUtf8());
}

EMSCRIPTEN_KEEPALIVE
char* die_get_file_info(const uint8_t* bytes, size_t size) {
    if (!bytes || size == 0) return nullptr;
    QByteArray buf(reinterpret_cast<const char*>(bytes), static_cast<qsizetype>(size));
    QBuffer dev(&buf);
    dev.open(QIODevice::ReadOnly);

    QSet<XBinary::FT> types = XBinary::getFileTypes(&dev, true);
    XBinary::FT preferred = XBinary::_getPrefFileType(&types);

    QJsonObject out;
    out["size"] = static_cast<qint64>(size);
    out["primaryFormat"] = XBinary::fileTypeIdToString(preferred);
    QJsonArray fmts;
    for (auto t : types) fmts.append(XBinary::fileTypeIdToString(t));
    out["allFormats"] = fmts;

    return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
}

EMSCRIPTEN_KEEPALIVE
char* die_compute_hashes(const uint8_t* bytes, size_t size) {
    if (!bytes || size == 0) return nullptr;
    QByteArray buf(reinterpret_cast<const char*>(bytes), static_cast<qsizetype>(size));

    QJsonObject out;
    out["md5"]    = QString::fromLatin1(QCryptographicHash::hash(buf, QCryptographicHash::Md5).toHex());
    out["sha1"]   = QString::fromLatin1(QCryptographicHash::hash(buf, QCryptographicHash::Sha1).toHex());
    out["sha256"] = QString::fromLatin1(QCryptographicHash::hash(buf, QCryptographicHash::Sha256).toHex());

    return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
}

EMSCRIPTEN_KEEPALIVE
char* die_compute_entropy(const uint8_t* bytes, size_t size, int windowSize) {
    if (!bytes || size == 0 || windowSize <= 0) return nullptr;

    const auto window = static_cast<size_t>(windowSize);
    QJsonArray points;

    for (size_t off = 0; off < size; off += window) {
        const size_t end = (off + window > size) ? size : off + window;
        const size_t n = end - off;

        int counts[256] = {0};
        for (size_t i = off; i < end; ++i) counts[bytes[i]]++;

        double H = 0.0;
        for (int b = 0; b < 256; ++b) {
            if (!counts[b]) continue;
            const double p = static_cast<double>(counts[b]) / static_cast<double>(n);
            H -= p * std::log2(p);
        }

        QJsonObject pt;
        pt["offset"] = static_cast<qint64>(off);
        pt["value"]  = H;
        points.append(pt);
    }

    return dupCString(QJsonDocument(points).toJson(QJsonDocument::Compact));
}

#define HOT_PRIMITIVE_GET_INT(NAME) \
    EMSCRIPTEN_KEEPALIVE int32_t die_binary_##NAME(void* session) { \
        auto* s = asSession(session); \
        if (!s || !s->script()) return 0; \
        return static_cast<int32_t>(s->script()->NAME()); \
    }

#define HOT_PRIMITIVE_GET_OFF_INT(NAME) \
    EMSCRIPTEN_KEEPALIVE int32_t die_binary_##NAME(void* session, int32_t nOffset) { \
        auto* s = asSession(session); \
        if (!s || !s->script()) return 0; \
        return static_cast<int32_t>(s->script()->NAME(nOffset)); \
    }

#define HOT_PRIMITIVE_GET_OFF_BE_INT(NAME) \
    EMSCRIPTEN_KEEPALIVE int32_t die_binary_##NAME(void* session, int32_t nOffset, int32_t bIsBigEndian) { \
        auto* s = asSession(session); \
        if (!s || !s->script()) return 0; \
        return static_cast<int32_t>(s->script()->NAME(nOffset, bIsBigEndian != 0)); \
    }

#define HOT_PRIMITIVE_GET_OFF_BE_FLOAT(NAME) \
    EMSCRIPTEN_KEEPALIVE double die_binary_##NAME(void* session, int32_t nOffset, int32_t bIsBigEndian) { \
        auto* s = asSession(session); \
        if (!s || !s->script()) return 0.0; \
        return static_cast<double>(s->script()->NAME(nOffset, bIsBigEndian != 0)); \
    }

#define HOT_PRIMITIVE_GET(NAME, RET)        HOT_PRIMITIVE_GET_INT(NAME)
#define HOT_PRIMITIVE_GET_OFF(NAME, RET)    HOT_PRIMITIVE_GET_OFF_INT(NAME)
#define HOT_PRIMITIVE_GET_OFF_BE(NAME, RET) HOT_PRIMITIVE_GET_OFF_BE_INT(NAME)

HOT_PRIMITIVE_GET(getSize, qint64)
HOT_PRIMITIVE_GET(Sz,      qint64)

HOT_PRIMITIVE_GET_OFF(readByte,    quint8)
HOT_PRIMITIVE_GET_OFF(readSByte,   qint16)
HOT_PRIMITIVE_GET_OFF(read_uint8,  quint8)
HOT_PRIMITIVE_GET_OFF(read_int8,   qint16)
HOT_PRIMITIVE_GET_OFF(U8,          quint8)
HOT_PRIMITIVE_GET_OFF(I8,          qint16)

HOT_PRIMITIVE_GET_OFF(readWord,    quint16)
HOT_PRIMITIVE_GET_OFF(readSWord,   qint16)
HOT_PRIMITIVE_GET_OFF(readDword,   quint32)
HOT_PRIMITIVE_GET_OFF(readSDword,  qint32)
HOT_PRIMITIVE_GET_OFF(readQword,   quint64)
HOT_PRIMITIVE_GET_OFF(readSQword,  qint64)
HOT_PRIMITIVE_GET_OFF_BE(read_uint16, quint16)
HOT_PRIMITIVE_GET_OFF_BE(read_int16,  qint16)
HOT_PRIMITIVE_GET_OFF_BE(read_uint24, quint32)
HOT_PRIMITIVE_GET_OFF_BE(read_int24,  qint32)
HOT_PRIMITIVE_GET_OFF_BE(read_uint32, quint32)
HOT_PRIMITIVE_GET_OFF_BE(read_int32,  qint32)
HOT_PRIMITIVE_GET_OFF_BE(read_uint64, quint64)
HOT_PRIMITIVE_GET_OFF_BE(read_int64,  qint64)
HOT_PRIMITIVE_GET_OFF_BE(U16, quint16)
HOT_PRIMITIVE_GET_OFF_BE(I16, qint16)
HOT_PRIMITIVE_GET_OFF_BE(U24, quint32)
HOT_PRIMITIVE_GET_OFF_BE(I24, qint32)
HOT_PRIMITIVE_GET_OFF_BE(U32, quint32)
HOT_PRIMITIVE_GET_OFF_BE(I32, qint32)
HOT_PRIMITIVE_GET_OFF_BE(U64, quint64)
HOT_PRIMITIVE_GET_OFF_BE(I64, qint64)
HOT_PRIMITIVE_GET_OFF_BE_FLOAT(read_float)
HOT_PRIMITIVE_GET_OFF_BE_FLOAT(read_double)
HOT_PRIMITIVE_GET_OFF_BE_FLOAT(read_float16)
HOT_PRIMITIVE_GET_OFF_BE_FLOAT(read_float32)
HOT_PRIMITIVE_GET_OFF_BE_FLOAT(read_float64)
HOT_PRIMITIVE_GET_OFF_BE_FLOAT(F16)
HOT_PRIMITIVE_GET_OFF_BE_FLOAT(F32)
HOT_PRIMITIVE_GET_OFF_BE_FLOAT(F64)

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_compare(void* session, const char* sig, int32_t nOffset) {
    auto* s = asSession(session);
    if (!s || !s->script() || !sig) return 0;
    return s->script()->compare(QString::fromUtf8(sig), nOffset) ? 1 : 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_compareEP(void* session, const char* sig, int32_t nOffset) {
    auto* s = asSession(session);
    if (!s || !s->script() || !sig) return 0;
    return s->script()->compareEP(QString::fromUtf8(sig), nOffset) ? 1 : 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_c(void* session, const char* sig, int32_t nOffset) {
    auto* s = asSession(session);
    if (!s || !s->script() || !sig) return 0;
    return s->script()->c(QString::fromUtf8(sig), nOffset) ? 1 : 0;
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_findSignature(void* session, int32_t nOffset, int32_t nSize, const char* sig) {
    auto* s = asSession(session);
    if (!s || !s->script() || !sig) return -1;
    return static_cast<int32_t>(s->script()->findSignature(nOffset, nSize, QString::fromUtf8(sig)));
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_fSig(void* session, int32_t nOffset, int32_t nSize, const char* sig) {
    auto* s = asSession(session);
    if (!s || !s->script() || !sig) return -1;
    return static_cast<int32_t>(s->script()->fSig(nOffset, nSize, QString::fromUtf8(sig)));
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_findString(void* session, int32_t nOffset, int32_t nSize, const char* str) {
    auto* s = asSession(session);
    if (!s || !s->script() || !str) return -1;
    return static_cast<int32_t>(s->script()->findString(nOffset, nSize, QString::fromUtf8(str)));
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_fStr(void* session, int32_t nOffset, int32_t nSize, const char* str) {
    auto* s = asSession(session);
    if (!s || !s->script() || !str) return -1;
    return static_cast<int32_t>(s->script()->fStr(nOffset, nSize, QString::fromUtf8(str)));
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_findByte(void* session, int32_t nOffset, int32_t nSize, int32_t v) {
    auto* s = asSession(session);
    if (!s || !s->script()) return -1;
    return static_cast<int32_t>(s->script()->findByte(nOffset, nSize, static_cast<quint8>(v & 0xFF)));
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_findWord(void* session, int32_t nOffset, int32_t nSize, int32_t v) {
    auto* s = asSession(session);
    if (!s || !s->script()) return -1;
    return static_cast<int32_t>(s->script()->findWord(nOffset, nSize, static_cast<quint16>(v & 0xFFFF)));
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_findDword(void* session, int32_t nOffset, int32_t nSize, int32_t v) {
    auto* s = asSession(session);
    if (!s || !s->script()) return -1;
    return static_cast<int32_t>(s->script()->findDword(nOffset, nSize, static_cast<quint32>(v)));
}

EMSCRIPTEN_KEEPALIVE
int32_t die_binary_isSignaturePresent(void* session, int32_t nOffset, int32_t nSize, const char* sig) {
    auto* s = asSession(session);
    if (!s || !s->script() || !sig) return 0;
    return s->script()->isSignaturePresent(nOffset, nSize, QString::fromUtf8(sig)) ? 1 : 0;
}

EMSCRIPTEN_KEEPALIVE
char* die_get_format_struct(void* session) {
    auto* s = asSession(session);
    if (!s || !s->binary()) return nullptr;
    QIODevice* dev = s->binary()->getDevice();
    if (!dev) return nullptr;

    const XBinary::FT ft = s->binary()->getFileType();

    QJsonArray top;
    for (const QString& method : XFileInfo::getMethodNames(ft)) {
        if (method == "Hash" || method == "Entropy" || method == "Check format") continue;

        XFileInfoModel model;
        XFileInfo::OPTIONS opts;
        opts.fileType = ft;
        opts.bComment = true;
        opts.sString  = method;  

        XBinary::PDSTRUCT pd = XBinary::createPdStruct();
        XFileInfo fi;
        fi.setData(dev, &model, opts, &pd);
        
        static_cast<XThreadObject*>(&fi)->process();

        const int rows = model.rowCount(QModelIndex());
        for (int r = 0; r < rows; ++r) {
            const QModelIndex idx = model.index(r, 0, QModelIndex());
            auto* item = static_cast<XFileInfoItem*>(idx.internalPointer());
            if (!item) continue;
            const QJsonObject node = fileInfoItemToJson(item);
            if (!node.value("children").toArray().isEmpty() || node.contains("value")) top.append(node);
        }
    }

    const std::string& cls = s->jsClass();
    if (cls == "PE")              appendPeStruct(static_cast<XPE*>(s->binary()), top);
    else if (cls == "ELF")        appendElfStruct(static_cast<XELF*>(s->binary()), top);
    else if (cls == "MACH")       appendMachStruct(static_cast<XMACH*>(s->binary()), top);

    return dupCString(QJsonDocument(top).toJson(QJsonDocument::Compact));
}

EMSCRIPTEN_KEEPALIVE
char* die_disasm_range(void* session, double startAddress, int count, int mode) {
    auto* s = asSession(session);
    if (!s || !s->binary()) return nullptr;
    XBinary* bin = s->binary();
    QIODevice* dev = bin->getDevice();
    if (!dev) return nullptr;

    if (count <= 0) count = 64;
    if (count > 4096) count = 4096;

    XBinary::PDSTRUCT pd = XBinary::createPdStruct();
    XBinary::_MEMORY_MAP mm = bin->getMemoryMap(XBinary::MAPMODE_UNKNOWN, &pd);

    const bool startWasOdd = (static_cast<XADDR>(startAddress) & XADDR(1)) != 0;

    XBinary::DM dm = XBinary::getDisasmMode(&mm);
    if (dm == XBinary::DM_ARM_LE || dm == XBinary::DM_ARM_BE) {
        const bool be = (mm.endian == XBinary::ENDIAN_BIG);
        bool wantThumb = false, wantCortexM = false;
        if (mode == 1)      {  }
        else if (mode == 2) wantThumb = true;
        else if (mode == 3) { wantThumb = true; wantCortexM = true; }
        else {  
            const QString arch = mm.sArch.toUpper();
            
            if (s->jsClass() == "PE" && (arch == QLatin1String("ARMNT") || arch == QLatin1String("THUMB")))
                wantThumb = true;
            else if (startWasOdd || (mm.nEntryPointAddress & XADDR(1)))
                wantThumb = true;
        }
        if (wantCortexM)     dm = XBinary::DM_CORTEXM;
        else if (wantThumb)  dm = be ? XBinary::DM_THUMB_BE : XBinary::DM_THUMB_LE;
    }
    const bool armFamily = (dm == XBinary::DM_ARM_LE || dm == XBinary::DM_ARM_BE ||
                            dm == XBinary::DM_THUMB_LE || dm == XBinary::DM_THUMB_BE ||
                            dm == XBinary::DM_CORTEXM);
    auto modeName = [](XBinary::DM m) -> const char* {
        switch (m) {
            case XBinary::DM_X86_16:     return "x86-16";
            case XBinary::DM_X86_32:     return "x86-32";
            case XBinary::DM_X86_64:     return "x86-64";
            case XBinary::DM_ARM_LE:     return "arm";
            case XBinary::DM_ARM_BE:     return "arm-be";
            case XBinary::DM_THUMB_LE:   return "thumb";
            case XBinary::DM_THUMB_BE:   return "thumb-be";
            case XBinary::DM_CORTEXM:    return "cortex-m";
            case XBinary::DM_AARCH64_LE: return "aarch64";
            case XBinary::DM_AARCH64_BE: return "aarch64-be";
            default:                     return "unknown";
        }
    };

    XDisasmCore core;
    core.setMode(dm);
    XDisasmAbstract::DISASM_OPTIONS dopts = {};
    dopts.bIsUppercase = false;
    dopts.bNoStrings   = false;

    const qint64 fileSize = bin->getSize();

    auto mapsToFile = [&](XADDR a) -> bool {
        const qint64 o = XBinary::addressToOffset(&mm, a);
        return o >= 0 && o < fileSize;
    };

    QJsonArray out;
    XADDR addr = static_cast<XADDR>(startAddress);
    
    if (armFamily) addr &= ~XADDR(1);
    const XADDR epAddr = armFamily ? (mm.nEntryPointAddress & ~XADDR(1)) : mm.nEntryPointAddress;

    if (startAddress <= 0.0 || !mapsToFile(addr)) {
        XADDR resolved = 0;
        bool found = false;
        if (epAddr != 0 && mapsToFile(epAddr)) {
            resolved = epAddr;
            found = true;
        }
        if (!found && s->jsClass() == "ELF") {
            auto* elf = static_cast<XELF*>(bin);
            const QList<XELF_DEF::Elf_Phdr> phdrs = elf->getElf_PhdrList(1000);
            for (const auto& ph : phdrs) {
                
                if (ph.p_type == XELF_DEF::S_PT_LOAD && (ph.p_flags & 0x1) &&
                    ph.p_filesz > 0 && mapsToFile(ph.p_vaddr)) {
                    resolved = ph.p_vaddr;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            for (const auto& rec : mm.listRecords) {
                if (rec.nOffset >= 0 && rec.nSize > 0 && mapsToFile(static_cast<XADDR>(rec.nAddress))) {
                    resolved = static_cast<XADDR>(rec.nAddress);
                    found = true;
                    break;
                }
            }
        }
        if (found) addr = resolved;
        
    }

    for (int i = 0; i < count; ++i) {
        const qint64 off = XBinary::addressToOffset(&mm, addr);
        if (off < 0 || off >= fileSize) break;   

        const XDisasmAbstract::DISASM_RESULT r = core.disAsm(dev, off, addr, dopts);
        QJsonObject ins;
        ins["address"] = static_cast<double>(addr);
        if (r.bIsValid && r.nSize > 0) {
            ins["size"]     = r.nSize;
            ins["hex"]      = QString::fromLatin1(bin->read_array(off, r.nSize).toHex());
            ins["mnemonic"] = r.sMnemonic;
            ins["operands"] = r.sOperands;
            if (r.relType != XDisasmAbstract::RELTYPE_NONE && r.nXrefToRelative) {
                ins["branch"] = static_cast<double>(r.nXrefToRelative);
            }
            out.append(ins);
            
            addr = (r.nNextAddress > addr) ? r.nNextAddress : (addr + static_cast<XADDR>(r.nSize));
        } else {
            
            const QByteArray ba = bin->read_array(off, 1);
            const quint8 b = ba.isEmpty() ? 0 : static_cast<quint8>(ba.at(0));
            ins["size"]     = 1;
            ins["hex"]      = QString::fromLatin1(QByteArray(1, static_cast<char>(b)).toHex());
            ins["mnemonic"] = QStringLiteral(".byte");
            ins["operands"] = QStringLiteral("0x") + QString::number(b, 16).rightJustified(2, QLatin1Char('0'));
            out.append(ins);
            addr += 1;
        }
    }

    QJsonObject result;
    result["mode"]  = QString::fromLatin1(modeName(dm));
    result["insns"] = out;
    return dupCString(QJsonDocument(result).toJson(QJsonDocument::Compact));
}

}  

namespace {

QString demangleIfMangled(const QString& name) {
    if (name.isEmpty()) return QString();
    if (!(name.startsWith("_Z") || name.startsWith("__Z") || name.startsWith("_R") ||
          name.startsWith("?") || name.startsWith("@_Z"))) {
        return QString();
    }
    QString d;
    d = XCppfilt::demangleGnuV3(name);  if (!d.isEmpty() && d != name) return d;
    d = XCppfilt::demangleRust(name);   if (!d.isEmpty() && d != name) return d;
    d = XCppfilt::demangleDLANG(name);  if (!d.isEmpty() && d != name) return d;
    return QString();
}

void addSymbol(QJsonArray& arr, const QString& name, const char* kind,
               qint64 address = -1, qint64 size = -1, const QString& type = QString(),
               const QString& bind = QString(), const QString& section = QString(),
               const QString& library = QString(), qint64 ordinal = -1) {
    QJsonObject o;
    o["name"] = name;
    const QString d = demangleIfMangled(name);
    if (!d.isEmpty()) o["demangled"] = d;
    o["kind"] = QString::fromLatin1(kind);
    if (address >= 0) o["address"] = static_cast<double>(address);
    if (size >= 0)    o["size"]    = static_cast<double>(size);
    if (!type.isEmpty())    o["type"]    = type;
    if (!bind.isEmpty())    o["bind"]    = bind;
    if (!section.isEmpty()) o["section"] = section;
    if (!library.isEmpty()) o["library"] = library;
    if (ordinal >= 0) o["ordinal"] = static_cast<double>(ordinal);
    arr.append(o);
}

constexpr int SYMBOLS_CAP = 60000;

const char* elfSymType(quint8 stInfo) {
    switch (stInfo & 0xF) {
        case 0:  return "NOTYPE";
        case 1:  return "OBJECT";
        case 2:  return "FUNC";
        case 3:  return "SECTION";
        case 4:  return "FILE";
        case 5:  return "COMMON";
        case 6:  return "TLS";
        case 10: return "GNU_IFUNC";
        default: return "";
    }
}
const char* elfSymBind(quint8 stInfo) {
    switch (stInfo >> 4) {
        case 0:  return "LOCAL";
        case 1:  return "GLOBAL";
        case 2:  return "WEAK";
        case 10: return "GNU_UNIQUE";
        default: return "";
    }
}

}  

extern "C" {

EMSCRIPTEN_KEEPALIVE
char* die_get_symbols(void* session) {
    auto* s = asSession(session);
    if (!s || !s->binary()) return nullptr;
    XBinary* bin = s->binary();
    const std::string& cls = s->jsClass();

    QJsonArray syms;
    bool truncated = false;
    auto room = [&]() { if (syms.size() >= SYMBOLS_CAP) { truncated = true; return false; } return true; };

    if (cls == "PE") {
        XPE* pe = static_cast<XPE*>(bin);
        XBinary::PDSTRUCT pd = XBinary::createPdStruct();
        
        const QList<XPE::IMPORT_RECORD> imps = pe->getImportRecords(&pd);
        for (const auto& ir : imps) {
            if (!room()) break;
            addSymbol(syms, ir.sFunction.isEmpty() ? QStringLiteral("(by ordinal)") : ir.sFunction,
                      "import", ir.nRVA >= 0 ? ir.nRVA : -1, -1, QString(), QString(), QString(), ir.sLibrary);
        }
        
        const XPE::EXPORT_HEADER ex = pe->getExport(false, &pd);
        for (const auto& ep : ex.listPositions) {
            if (!room()) break;
            addSymbol(syms, ep.sFunctionName.isEmpty() ? QStringLiteral("(unnamed)") : ep.sFunctionName,
                      "export", ep.nRVA, -1, QString(), QString(), QString(), ex.sName, ep.nOrdinal);
        }
    } else if (cls == "ELF") {
        XELF* elf = static_cast<XELF*>(bin);
        QList<XELF_DEF::Elf_Shdr> shdrs = elf->getElf_ShdrList(10000);
        for (qint32 si = 0; si < shdrs.count(); ++si) {
            const quint32 idx   = static_cast<quint32>(si);
            const quint32 stype = XELF::getElf_Shdr_type(idx, &shdrs);
            if (stype != 2  && stype != 11 ) continue;
            const quint32 link  = XELF::getElf_Shdr_link(idx, &shdrs);
            const quint64 soff  = XELF::getElf_Shdr_offset(idx, &shdrs);
            const quint64 ssize = XELF::getElf_Shdr_size(idx, &shdrs);
            const QList<XELF_DEF::Elf_Sym> elfSyms =
                elf->getElf_SymList(static_cast<qint64>(soff), static_cast<qint64>(ssize));
            for (const auto& es : elfSyms) {
                if (!room()) break;
                QString name = elf->getStringFromSection(es.st_name, link);
                if (name.isEmpty() && (es.st_info & 0xF) == 4 ) name = QStringLiteral("(file)");
                if (name.isEmpty()) continue;   
                const char* kind = (es.st_shndx == 0) ? "import"
                                 : ((es.st_info >> 4) == 1 || (es.st_info >> 4) == 2) ? "export"
                                 : "symbol";
                addSymbol(syms, name, kind,
                          es.st_shndx == 0 ? -1 : static_cast<qint64>(es.st_value),
                          static_cast<qint64>(es.st_size),
                          QString::fromLatin1(elfSymType(es.st_info)),
                          QString::fromLatin1(elfSymBind(es.st_info)),
                          es.st_shndx == 0 ? QStringLiteral("UND")
                            : (es.st_shndx == 0xfff1 ? QStringLiteral("ABS")
                               : QString::number(es.st_shndx)));
            }
            if (truncated) break;
        }
    } else if (cls == "MACH" || cls == "MACHOFAT") {
        XMACH* mach = static_cast<XMACH*>(bin);
        XBinary::_MEMORY_MAP mm = bin->getMemoryMap();
        const bool be = (mm.endian == XBinary::ENDIAN_BIG);
        QList<XMACH::COMMAND_RECORD> cmds = mach->getCommandRecords();
        
        qint64 strOff = -1;
        QList<XMACH::COMMAND_RECORD> symtabCmds = XMACH::getCommandRecords(0x2, &cmds);
        if (!symtabCmds.isEmpty()) {
            const qint64 cOff = symtabCmds.first().nStructOffset;
            strOff = static_cast<qint64>(bin->read_uint32(cOff + 16, be));
        }
        const QList<XMACH::NLIST_RECORD> nl = mach->getNlistRecords(&cmds);
        for (const auto& rec : nl) {
            if (!room()) break;
            const quint32 strx  = rec.bIs64 ? rec.s.nlist64.n_strx  : rec.s.nlist32.n_strx;
            const quint8  ntype = rec.bIs64 ? rec.s.nlist64.n_type  : rec.s.nlist32.n_type;
            const quint8  nsect = rec.bIs64 ? rec.s.nlist64.n_sect  : rec.s.nlist32.n_sect;
            const quint64 nval  = rec.bIs64 ? rec.s.nlist64.n_value : rec.s.nlist32.n_value;
            QString name;
            if (strOff >= 0 && strx) name = bin->read_ansiString(strOff + strx, 1024);
            if (name.isEmpty()) continue;
            const bool ext   = (ntype & 0x01) != 0;            
            const quint8 typ = ntype & 0x0e;                   
            const char* kind = (typ == 0x00 ) ? "import"
                             : (ext ? "export" : "symbol");
            addSymbol(syms, name, kind,
                      (typ == 0x00) ? -1 : static_cast<qint64>(nval), -1,
                      QString(), ext ? QStringLiteral("GLOBAL") : QStringLiteral("LOCAL"),
                      nsect ? QString::number(nsect) : QString());
        }
    }

    QJsonObject out;
    out["symbols"]   = syms;
    out["truncated"] = truncated;
    return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
}

}  

extern "C" {
#include "yara.h"
}

namespace {

struct YaraCompileCtx { QJsonArray errors; QString currentUnit; };

void yaraCompileCb(int errorLevel, const char* , int lineNumber,
                   const YR_RULE* , const char* message, void* userData) {
    auto* c = static_cast<YaraCompileCtx*>(userData);
    QJsonObject e;
    e["level"]   = (errorLevel == YARA_ERROR_LEVEL_ERROR) ? "error" : "warning";
    e["line"]    = lineNumber;
    e["message"] = QString::fromUtf8(message ? message : "");
    if (!c->currentUnit.isEmpty()) e["unit"] = c->currentUnit;
    c->errors.append(e);
}

struct YaraScanCtx { QJsonArray matches; };
constexpr int YARA_MATCH_CAP = 5000;
constexpr int YARA_STRINGS_PER_RULE_CAP = 200;
constexpr int YARA_DATA_PREVIEW = 32;

int yaraScanCb(YR_SCAN_CONTEXT* context, int message, void* messageData, void* userData) {
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;
    auto* s = static_cast<YaraScanCtx*>(userData);
    if (s->matches.size() >= YARA_MATCH_CAP) return CALLBACK_ABORT;
    YR_RULE* rule = static_cast<YR_RULE*>(messageData);

    QJsonObject m;
    m["rule"]      = QString::fromUtf8(rule->identifier ? rule->identifier : "");
    m["namespace"] = QString::fromUtf8((rule->ns && rule->ns->name) ? rule->ns->name : "default");

    QJsonArray tags;
    const char* tag = nullptr;
    yr_rule_tags_foreach(rule, tag) tags.append(QString::fromUtf8(tag));
    if (!tags.isEmpty()) m["tags"] = tags;

    QJsonObject meta;
    YR_META* mt = nullptr;
    yr_rule_metas_foreach(rule, mt) {
        const QString key = QString::fromUtf8(mt->identifier ? mt->identifier : "");
        if (mt->type == META_TYPE_INTEGER)      meta[key] = static_cast<double>(mt->integer);
        else if (mt->type == META_TYPE_BOOLEAN) meta[key] = (mt->integer != 0);
        else                                    meta[key] = QString::fromUtf8(mt->string ? mt->string : "");
    }
    if (!meta.isEmpty()) m["meta"] = meta;

    QJsonArray strings;
    YR_STRING* str = nullptr;
    yr_rule_strings_foreach(rule, str) {
        YR_MATCH* match = nullptr;
        yr_string_matches_foreach(context, str, match) {
            if (strings.size() >= YARA_STRINGS_PER_RULE_CAP) break;
            QJsonObject so;
            so["id"]     = QString::fromUtf8(str->identifier ? str->identifier : "");
            so["offset"] = static_cast<double>(match->base + match->offset);
            int dlen = static_cast<int>(match->data_length);
            if (dlen < 0) dlen = 0;
            if (dlen > YARA_DATA_PREVIEW) dlen = YARA_DATA_PREVIEW;
            so["dataHex"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(match->data), dlen).toHex());
            if (static_cast<int>(match->data_length) > YARA_DATA_PREVIEW) so["truncated"] = true;
            strings.append(so);
        }
        if (strings.size() >= YARA_STRINGS_PER_RULE_CAP) break;
    }
    if (!strings.isEmpty()) m["strings"] = strings;

    s->matches.append(m);
    return CALLBACK_CONTINUE;
}

bool g_yaraInited = false;
bool ensureYara() {
    if (g_yaraInited) return true;
    if (yr_initialize() != ERROR_SUCCESS) return false;
    g_yaraInited = true;
    return true;
}

char* yaraErrJson(const QString& msg) {
    QJsonObject out; out["ok"] = false;
    QJsonArray errs; QJsonObject e; e["level"] = "error"; e["line"] = 0; e["message"] = msg; errs.append(e);
    out["errors"] = errs;
    return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
}

}  

extern "C" {

EMSCRIPTEN_KEEPALIVE
char* die_yara_scan(const uint8_t* bytes, size_t size, const char* unitsJson) {
    if (!bytes || !unitsJson) return nullptr;
    if (!ensureYara()) return yaraErrJson("yr_initialize failed");

    QJsonParseError pe{};
    const QJsonDocument doc = QJsonDocument::fromJson(QByteArray(unitsJson), &pe);
    if (pe.error != QJsonParseError::NoError || !doc.isArray())
        return yaraErrJson("bad units JSON: " + pe.errorString());
    const QJsonArray units = doc.array();
    if (units.isEmpty()) return yaraErrJson("no rule units supplied");

    QJsonObject out;
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS || !compiler)
        return yaraErrJson("yr_compiler_create failed");

    YaraCompileCtx cctx;
    yr_compiler_set_callback(compiler, yaraCompileCb, &cctx);

    int nErrors = 0;
    for (const QJsonValue& uv : units) {
        const QJsonObject u = uv.toObject();
        const QString ns  = u.value("ns").toString();
        const QString src = u.value("src").toString();
        if (src.trimmed().isEmpty()) continue;
        cctx.currentUnit = ns;
        const QByteArray nsUtf8 = ns.toUtf8();
        nErrors += yr_compiler_add_string(compiler, src.toUtf8().constData(),
                                          ns.isEmpty() ? nullptr : nsUtf8.constData());
    }
    cctx.currentUnit.clear();

    if (nErrors > 0) {
        yr_compiler_destroy(compiler);
        out["ok"] = false;
        out["errors"] = cctx.errors;
        return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
    }

    YR_RULES* rules = nullptr;
    const int gr = yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
    if (gr != ERROR_SUCCESS || !rules) {
        out["ok"] = false;
        if (cctx.errors.isEmpty()) { QJsonObject e; e["level"] = "error"; e["line"] = 0; e["message"] = "yr_compiler_get_rules failed"; cctx.errors.append(e); }
        out["errors"] = cctx.errors;
        return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
    }

    YaraScanCtx sctx;
    const int sr = yr_rules_scan_mem(rules, bytes, size,  0, yaraScanCb, &sctx,  60);
    yr_rules_destroy(rules);

    out["ok"]      = true;
    out["matches"] = sctx.matches;
    if (!cctx.errors.isEmpty()) out["errors"] = cctx.errors;   
    if (sr == ERROR_SCAN_TIMEOUT) out["timeout"] = true;
    else if (sr == ERROR_TOO_MANY_MATCHES) out["truncated"] = true;
    else if (sr != ERROR_SUCCESS) out["scanError"] = sr;
    return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
}

}  

#include "xmime.h"

extern "C" {

EMSCRIPTEN_KEEPALIVE
char* die_get_mime(const uint8_t* bytes, size_t size) {
    if (!bytes || size == 0) return nullptr;
    QByteArray buf(reinterpret_cast<const char*>(bytes), static_cast<qsizetype>(size));
    QBuffer dev(&buf);
    dev.open(QIODevice::ReadOnly);
    QJsonArray out;
    for (const QString& t : XMIME::getTypes(&dev, true)) out.append(t);
    return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
}

}  

#include "xextractor.h"

extern "C" {

EMSCRIPTEN_KEEPALIVE
char* die_extract(void* session) {
    auto* s = asSession(session);
    if (!s || !s->binary()) return nullptr;
    QIODevice* dev = s->binary()->getDevice();
    if (!dev) return nullptr;

    XExtractor::OPTIONS opts = XExtractor::getDefaultOptions();
    opts.fileType = s->binary()->getFileType();
    opts.emode    = XExtractor::EMODE_FORMAT;
    opts.bAllTypes = false;   

    XBinary::PDSTRUCT pd = XBinary::createPdStruct();
    const QVector<XExtractor::RECORD> recs = XExtractor::scanDevice(dev, opts, &pd);

    QJsonArray out;
    for (const auto& r : recs) {
        QJsonObject o;
        o["offset"] = static_cast<double>(r.nOffset);
        o["size"]   = static_cast<double>(r.nSize);
        o["type"]   = XBinary::fileTypeIdToString(r.fileType);
        if (!r.sName.isEmpty())   o["name"]   = r.sName;
        if (!r.sExt.isEmpty())    o["ext"]    = r.sExt;
        if (!r.sString.isEmpty()) o["string"] = r.sString;
        out.append(o);
    }
    return dupCString(QJsonDocument(out).toJson(QJsonDocument::Compact));
}

}  
