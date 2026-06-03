#include "Session.h"

#include "WebFileDevice.h"

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>

#include "xbinary.h"
#include "xformats.h"

#include "xpe.h"
#include "xelf.h"
#include "xmach.h"
#include "xmachofat.h"
#include "xne.h"
#include "xle.h"
#include "xmsdos.h"
#include "xcom.h"
#include "xdex.h"
#include "xpdf.h"
#include "xcfbf.h"
#include "xjpeg.h"
#include "xpng.h"
#include "xrar.h"
#include "xzip.h"
#include "xjar.h"
#include "xapk.h"
#include "xipa.h"
#include "xnpm.h"
#include "xiso9660.h"
#include "xamigahunk.h"
#include "xatarist.h"
#include "xjavaclass.h"
#include "xpyc.h"
#include "xdos16.h"

#include "binary_script.h"
#include "com_script.h"
#include "pe_script.h"
#include "elf_script.h"
#include "mach_script.h"
#include "machofat_script.h"
#include "ne_script.h"
#include "le_script.h"
#include "lx_script.h"
#include "msdos_script.h"
#include "archive_script.h"
#include "image_script.h"
#include "rar_script.h"
#include "iso9660_script.h"
#include "zip_script.h"
#include "jar_script.h"
#include "apk_script.h"
#include "ipa_script.h"
#include "npm_script.h"
#include "dex_script.h"
#include "amiga_script.h"
#include "atarist_script.h"
#include "javaclass_script.h"
#include "pyc_script.h"
#include "pdf_script.h"
#include "cfbf_script.h"
#include "jpeg_script.h"
#include "png_script.h"
#include "dos16m_script.h"
#include "dos4g_script.h"

#include "xscanengine.h"

namespace die_web {

Session::Session() = default;
Session::~Session() = default;

namespace {

Binary_Script::OPTIONS makeDefaultOptions() {
    Binary_Script::OPTIONS o;
    o.bIsDeepScan       = true;
    o.bIsHeuristicScan  = true;
    o.bIsAggressiveScan = false;
    o.bIsRecursiveScan  = false;
    o.bIsOverlayScan    = true;
    o.bIsResourcesScan  = true;
    o.bIsArchivesScan   = true;
    o.bIsVerbose        = false;
    o.bIsProfiling      = false;
    o.sScanID           = QString();
    return o;
}

void applyOptionsJson(Binary_Script::OPTIONS& o, const char* optionsJson) {
    if (!optionsJson || !*optionsJson) return;
    QJsonParseError pe{};
    const QJsonDocument d = QJsonDocument::fromJson(QByteArray(optionsJson), &pe);
    if (pe.error != QJsonParseError::NoError || !d.isObject()) return;
    const QJsonObject j = d.object();
    const auto b = [&](const char* k, bool dflt) { return j.contains(k) ? j.value(k).toBool(dflt) : dflt; };
    o.bIsDeepScan       = b("deepScan",       o.bIsDeepScan);
    o.bIsHeuristicScan  = b("heuristicScan",  o.bIsHeuristicScan);
    o.bIsAggressiveScan = b("aggressiveScan", o.bIsAggressiveScan);
    o.bIsRecursiveScan  = b("recursiveScan",  o.bIsRecursiveScan);
    o.bIsOverlayScan    = b("overlayScan",    o.bIsOverlayScan);
    o.bIsResourcesScan  = b("resourcesScan",  o.bIsResourcesScan);
    o.bIsArchivesScan   = b("archivesScan",   o.bIsArchivesScan);
    o.bIsVerbose        = b("verbose",        o.bIsVerbose);
}

struct Factory {
    XBinary*       binary;
    Binary_Script* script;
    const char*    jsClass;
};

Factory makeFactory(QIODevice* device, XBinary::FT ft, Binary_Script::OPTIONS* opts,
                    XBinary::PDSTRUCT* pd) {
    constexpr auto FILEPART = XBinary::FILEPART_HEADER;

    if (XBinary::checkFileType(XBinary::FT_BINARY, ft)) {
        auto* b = new XBinary(device);
        return {b, new Binary_Script(b, FILEPART, opts, pd), "Binary"};
    }
    if (XBinary::checkFileType(XBinary::FT_COM, ft)) {
        auto* b = new XCOM(device);
        return {b, new COM_Script(b, FILEPART, opts, pd), "COM"};
    }
    if (XBinary::checkFileType(XBinary::FT_PE, ft)) {
        auto* b = new XPE(device);
        return {b, new PE_Script(b, FILEPART, opts, pd), "PE"};
    }
    if (XBinary::checkFileType(XBinary::FT_ELF, ft)) {
        auto* b = new XELF(device);
        return {b, new ELF_Script(b, FILEPART, opts, pd), "ELF"};
    }
    if (XBinary::checkFileType(XBinary::FT_MACHO, ft)) {
        auto* b = new XMACH(device);
        return {b, new MACH_Script(b, FILEPART, opts, pd), "MACH"};
    }
    if (XBinary::checkFileType(XBinary::FT_MACHOFAT, ft)) {
        auto* b = new XMACHOFat(device);
        return {b, new MACHOFAT_Script(b, FILEPART, opts, pd), "MACHOFAT"};
    }
    if (XBinary::checkFileType(XBinary::FT_NE, ft)) {
        auto* b = new XNE(device);
        return {b, new NE_Script(b, FILEPART, opts, pd), "NE"};
    }
    if (XBinary::checkFileType(XBinary::FT_LE, ft)) {
        auto* b = new XLE(device);
        return {b, new LE_Script(b, FILEPART, opts, pd), "LE"};
    }
    if (XBinary::checkFileType(XBinary::FT_LX, ft)) {
        auto* b = new XLE(device);
        return {b, new LX_Script(b, FILEPART, opts, pd), "LX"};
    }
    if (XBinary::checkFileType(XBinary::FT_MSDOS, ft)) {
        auto* b = new XMSDOS(device);
        return {b, new MSDOS_Script(b, FILEPART, opts, pd), "MSDOS"};
    }
    if (XBinary::checkFileType(XBinary::FT_DEX, ft)) {
        auto* b = new XDEX(device);
        return {b, new DEX_Script(b, FILEPART, opts, pd), "DEX"};
    }
    if (XBinary::checkFileType(XBinary::FT_PDF, ft)) {
        auto* b = new XPDF(device);
        return {b, new PDF_Script(b, FILEPART, opts, pd), "PDF"};
    }
    if (XBinary::checkFileType(XBinary::FT_CFBF, ft)) {
        auto* b = new XCFBF(device);
        return {b, new CFBF_Script(b, FILEPART, opts, pd), "CFBF"};
    }
    if (XBinary::checkFileType(XBinary::FT_JPEG, ft)) {
        auto* b = new XJpeg(device);
        return {b, new Jpeg_Script(b, FILEPART, opts, pd), "Jpeg"};
    }
    if (XBinary::checkFileType(XBinary::FT_PNG, ft)) {
        auto* b = new XPNG(device);
        return {b, new PNG_Script(b, FILEPART, opts, pd), "PNG"};
    }
    if (XBinary::checkFileType(XBinary::FT_RAR, ft)) {
        auto* b = new XRar(device);
        return {b, new RAR_Script(b, FILEPART, opts, pd), "RAR"};
    }
    if (XBinary::checkFileType(XBinary::FT_ZIP, ft)) {
        auto* b = new XZip(device);
        return {b, new ZIP_Script(b, FILEPART, opts, pd), "ZIP"};
    }
    if (XBinary::checkFileType(XBinary::FT_JAR, ft)) {
        auto* b = new XJAR(device);
        return {b, new JAR_Script(b, FILEPART, opts, pd), "JAR"};
    }
    if (XBinary::checkFileType(XBinary::FT_APK, ft)) {
        auto* b = new XAPK(device);
        return {b, new APK_Script(b, FILEPART, opts, pd), "APK"};
    }
    if (XBinary::checkFileType(XBinary::FT_IPA, ft)) {
        auto* b = new XIPA(device);
        return {b, new IPA_Script(b, FILEPART, opts, pd), "IPA"};
    }
    if (XBinary::checkFileType(XBinary::FT_NPM, ft)) {
        auto* b = new XNPM(device);
        return {b, new NPM_Script(b, FILEPART, opts, pd), "NPM"};
    }
    if (XBinary::checkFileType(XBinary::FT_ISO9660, ft)) {
        auto* b = new XISO9660(device);
        return {b, new ISO9660_Script(b, FILEPART, opts, pd), "ISO9660"};
    }
    if (XBinary::checkFileType(XBinary::FT_AMIGAHUNK, ft)) {
        auto* b = new XAmigaHunk(device);
        return {b, new Amiga_Script(b, FILEPART, opts, pd), "Amiga"};
    }
    if (XBinary::checkFileType(XBinary::FT_ATARIST, ft)) {
        auto* b = new XAtariST(device);
        return {b, new AtariST_Script(b, FILEPART, opts, pd), "AtariST"};
    }
    if (XBinary::checkFileType(XBinary::FT_JAVACLASS, ft)) {
        auto* b = new XJavaClass(device);
        return {b, new JavaClass_Script(b, FILEPART, opts, pd), "JavaClass"};
    }
    if (XBinary::checkFileType(XBinary::FT_PYC, ft)) {
        auto* b = new XPYC(device);
        return {b, new PYC_Script(b, FILEPART, opts, pd), "PYC"};
    }
    if (XBinary::checkFileType(XBinary::FT_DOS16M, ft)) {
        auto* b = new XDOS16(device);
        return {b, new DOS16M_Script(b, FILEPART, opts, pd), "DOS16M"};
    }
    if (XBinary::checkFileType(XBinary::FT_DOS4G, ft)) {
        auto* b = new XDOS16(device);
        return {b, new DOS4G_Script(b, FILEPART, opts, pd), "DOS4G"};
    }

    auto* b = new XBinary(device);
    return {b, new Binary_Script(b, FILEPART, opts, pd), "Binary"};
}

}

bool Session::open(const uint8_t* bytes, size_t size, const char* optionsJson) {
    m_bytesOwned.assign(bytes, bytes + size);
    m_device.reset(new WebFileDevice(m_bytesOwned.data(), static_cast<qint64>(size)));

    QSet<XBinary::FT> types = XBinary::getFileTypes(m_device.get(), true);
    XBinary::FT ft = XBinary::_getPrefFileType(&types);

    m_options = makeDefaultOptions();
    applyOptionsJson(m_options, optionsJson);
    m_pd = XBinary::PDSTRUCT{};

    Factory f = makeFactory(m_device.get(), ft, &m_options, &m_pd);
    if (!f.binary || !f.script) return false;

    m_binary.reset(f.binary);
    m_script.reset(f.script);
    m_jsClass = f.jsClass;
    return true;
}

}
