
#include "Session.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>
#include <QStringList>
#include <QVariant>

#include <cstdlib>
#include <cstring>

#include "amiga_script.h"
#include "apk_script.h"
#include "archive_script.h"
#include "binary_script.h"
#include "dex_script.h"
#include "elf_script.h"
#include "iso9660_script.h"
#include "jar_script.h"
#include "jpeg_script.h"
#include "mach_script.h"
#include "msdos_script.h"
#include "npm_script.h"
#include "pdf_script.h"
#include "pe_script.h"
#include "png_script.h"
#include "pyc_script.h"
#include "xamigahunk.h"
#include "xapk.h"
#include "xatarist.h"
#include "xbinary.h"
#include "xcfbf.h"
#include "xcom.h"
#include "xdex.h"
#include "xdos16.h"
#include "xelf.h"
#include "xformats.h"
#include "xipa.h"
#include "xiso9660.h"
#include "xjar.h"
#include "xjavaclass.h"
#include "xjpeg.h"
#include "xle.h"
#include "xmach.h"
#include "xmachofat.h"
#include "xmsdos.h"
#include "xne.h"
#include "xnpm.h"
#include "xpdf.h"
#include "xpe.h"
#include "xpng.h"
#include "xpyc.h"
#include "xrar.h"
#include "xzip.h"

namespace {

char* mkResult(const QJsonValue& v) {
    QJsonObject env;
    env["result"] = v;
    QByteArray bytes = QJsonDocument(env).toJson(QJsonDocument::Compact);
    char* out = static_cast<char*>(std::malloc(static_cast<size_t>(bytes.size()) + 1));
    if (!out) return nullptr;
    std::memcpy(out, bytes.constData(), static_cast<size_t>(bytes.size()));
    out[bytes.size()] = '\0';
    return out;
}

}  

extern "C" char* die_dispatch_invoke(die_web::Session* session, int methodId,
                                     const char* argsJson) {
    if (!session || !session->script()) return nullptr;

    QJsonArray args;
    if (argsJson && *argsJson) {
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray(argsJson));
        if (doc.isArray()) args = doc.array();
    }
    Q_UNUSED(args);

    switch (methodId) {
      case 0: { 
        auto* obj = static_cast<APK_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getAndroidManifest(); return mkResult(QJsonValue(retval));
      }
      case 1: { 
        auto* obj = static_cast<APK_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString retval = obj->getAndroidManifestRecord(arg0); return mkResult(QJsonValue(retval));
      }
      case 2: { 
        auto* obj = static_cast<Amiga_Script*>(session->script());
        if (!obj) return nullptr;
        qint32 arg0 = args[0].toVariant().toInt();
        quint16 retval = obj->getHunkIdByNumber(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 3: { 
        auto* obj = static_cast<Amiga_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getNumberOfHunks(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 4: { 
        auto* obj = static_cast<Archive_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isArchiveRecordPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 5: { 
        auto* obj = static_cast<Archive_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isArchiveRecordPresentExp(arg0); return mkResult(QJsonValue(retval));
      }
      case 6: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        bool arg2 = args[2].toBool();
        QList<QVariant> retval = obj->BA(arg0, arg1, arg2);
        QJsonArray ja = QJsonArray::fromVariantList(retval);
        return mkResult(QJsonValue(ja));
      }
      case 7: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        float retval = obj->F16(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 8: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        float retval = obj->F32(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 9: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        double retval = obj->F64(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 10: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        qint16 retval = obj->I16(arg0, arg1); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 11: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        qint32 retval = obj->I24(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 12: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        qint32 retval = obj->I32(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 13: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        qint64 retval = obj->I64(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 14: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint16 retval = obj->I8(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 15: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 retval = obj->OffsetToRVA(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 16: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 retval = obj->OffsetToVA(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 17: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 retval = obj->RVAToOffset(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 18: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->SA(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 19: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        QString retval = obj->SC(arg0, arg1, arg2); return mkResult(QJsonValue(retval));
      }
      case 20: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->SU16(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 21: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->SU8(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 22: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->Sz(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 23: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint16 retval = obj->U16(arg0, arg1); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 24: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint32 retval = obj->U24(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 25: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint32 retval = obj->U32(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 26: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint64 retval = obj->U64(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 27: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        quint8 retval = obj->U8(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 28: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        QString retval = obj->UCSD(arg0); return mkResult(QJsonValue(retval));
      }
      case 29: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 retval = obj->VAToOffset(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 30: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        quint32 retval = obj->adler32(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 31: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        quint64 arg0 = args[0].toVariant().toULongLong();
        QString retval = obj->bytesCountToString(arg0); return mkResult(QJsonValue(retval));
      }
      case 32: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint64 arg1 = args[1].toVariant().toLongLong();
        bool retval = obj->c(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 33: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        quint32 retval = obj->calculateCRC32(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 34: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        double retval = obj->calculateEntropy(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 35: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->calculateMD5(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 36: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString retval = obj->cleanString(arg0); return mkResult(QJsonValue(retval));
      }
      case 37: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint64 arg1 = args[1].toVariant().toLongLong();
        bool retval = obj->compare(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 38: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint64 arg1 = args[1].toVariant().toLongLong();
        bool retval = obj->compareEP(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 39: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint64 arg1 = args[1].toVariant().toLongLong();
        bool retval = obj->compareOverlay(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 40: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        quint16 arg2 = static_cast<quint16>(args[2].toInt());
        quint16 retval = obj->crc16(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 41: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        quint32 arg2 = args[2].toVariant().toUInt();
        quint32 retval = obj->crc32(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 42: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        QList<QVariant> retval = obj->decompressBytes(arg0, arg1, arg2);
        QJsonArray ja = QJsonArray::fromVariantList(retval);
        return mkResult(QJsonValue(ja));
      }
      case 43: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        qint64 retval = obj->detectGZIP(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 44: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        qint64 retval = obj->detectZIP(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 45: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        qint64 retval = obj->detectZLIB(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 46: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        QString arg1 = args[1].toString();
        qint64 retval = obj->endTiming(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 47: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        qint64 retval = obj->fSig(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 48: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        qint64 retval = obj->fStr(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 49: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        quint8 arg2 = static_cast<quint8>(args[2].toInt());
        qint64 retval = obj->findByte(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 50: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        quint32 arg2 = args[2].toVariant().toUInt();
        qint64 retval = obj->findDword(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 51: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        qint64 retval = obj->findSignature(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 52: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        qint64 retval = obj->findString(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 53: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        quint16 arg2 = static_cast<quint16>(args[2].toInt());
        qint64 retval = obj->findWord(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 54: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        qint64 retval = obj->find_ansiString(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 55: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        qint64 retval = obj->find_unicodeString(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 56: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        qint64 retval = obj->find_utf8String(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 57: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->getAddressOfEntryPoint(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 58: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        qint64 retval = obj->getCompressedDataSize(arg0, arg1, arg2); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 59: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint32 retval = obj->getDisasmLength(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 60: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 retval = obj->getDisasmNextAddress(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 61: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        QString retval = obj->getDisasmString(arg0); return mkResult(QJsonValue(retval));
      }
      case 62: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->getEntryPointOffset(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 63: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getFileBaseName(); return mkResult(QJsonValue(retval));
      }
      case 64: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getFileCompleteSuffix(); return mkResult(QJsonValue(retval));
      }
      case 65: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getFileDirectory(); return mkResult(QJsonValue(retval));
      }
      case 66: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getFileFormatName(); return mkResult(QJsonValue(retval));
      }
      case 67: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getFileFormatOptions(); return mkResult(QJsonValue(retval));
      }
      case 68: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getFileFormatVersion(); return mkResult(QJsonValue(retval));
      }
      case 69: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getFileSuffix(); return mkResult(QJsonValue(retval));
      }
      case 70: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QStringList retval = obj->getFormatMessages();
        QJsonArray ja; for (const QString& s : retval) ja.append(s);
        return mkResult(QJsonValue(ja));
      }
      case 71: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getGeneralOptions(); return mkResult(QJsonValue(retval));
      }
      case 72: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getHeaderString(); return mkResult(QJsonValue(retval));
      }
      case 73: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->getImageBase(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 74: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QStringList retval = obj->getListOfCompressionMethods();
        QJsonArray ja; for (const QString& s : retval) ja.append(s);
        return mkResult(QJsonValue(ja));
      }
      case 75: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getOperationSystemName(); return mkResult(QJsonValue(retval));
      }
      case 76: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getOperationSystemOptions(); return mkResult(QJsonValue(retval));
      }
      case 77: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getOperationSystemVersion(); return mkResult(QJsonValue(retval));
      }
      case 78: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->getOverlayOffset(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 79: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->getOverlaySize(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 80: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        QString retval = obj->getScanID(); return mkResult(QJsonValue(retval));
      }
      case 81: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->getSignature(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 82: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->getSize(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 83: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->getStartOffset(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 84: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->getString(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 85: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->is16(); return mkResult(QJsonValue(retval));
      }
      case 86: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->is32(); return mkResult(QJsonValue(retval));
      }
      case 87: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->is64(); return mkResult(QJsonValue(retval));
      }
      case 88: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isAggressiveScan(); return mkResult(QJsonValue(retval));
      }
      case 89: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isChecksumCorrect(); return mkResult(QJsonValue(retval));
      }
      case 90: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isDebugBuild(); return mkResult(QJsonValue(retval));
      }
      case 91: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isDebugData(); return mkResult(QJsonValue(retval));
      }
      case 92: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isDeepScan(); return mkResult(QJsonValue(retval));
      }
      case 93: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isEntryPointCorrect(); return mkResult(QJsonValue(retval));
      }
      case 94: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isExportTableCorrect(); return mkResult(QJsonValue(retval));
      }
      case 95: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isFileAlignmentCorrect(); return mkResult(QJsonValue(retval));
      }
      case 96: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isFilePart(); return mkResult(QJsonValue(retval));
      }
      case 97: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isHeaderCorrect(); return mkResult(QJsonValue(retval));
      }
      case 98: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isHeuristicScan(); return mkResult(QJsonValue(retval));
      }
      case 99: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isImportTableCorrect(); return mkResult(QJsonValue(retval));
      }
      case 100: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isOverlay(); return mkResult(QJsonValue(retval));
      }
      case 101: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isOverlayPresent(); return mkResult(QJsonValue(retval));
      }
      case 102: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isOverlayScan(); return mkResult(QJsonValue(retval));
      }
      case 103: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isPlainText(); return mkResult(QJsonValue(retval));
      }
      case 104: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isProfiling(); return mkResult(QJsonValue(retval));
      }
      case 105: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isRecursiveScan(); return mkResult(QJsonValue(retval));
      }
      case 106: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isReleaseBuild(); return mkResult(QJsonValue(retval));
      }
      case 107: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isRelocsTableCorrect(); return mkResult(QJsonValue(retval));
      }
      case 108: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isResource(); return mkResult(QJsonValue(retval));
      }
      case 109: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isResourcesTableCorrect(); return mkResult(QJsonValue(retval));
      }
      case 110: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isSectionAlignmentCorrect(); return mkResult(QJsonValue(retval));
      }
      case 111: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isSectionsTableCorrect(); return mkResult(QJsonValue(retval));
      }
      case 112: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        QString arg1 = args[1].toString();
        bool retval = obj->isSignatureInSectionPresent(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 113: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        bool retval = obj->isSignaturePresent(arg0, arg1, arg2); return mkResult(QJsonValue(retval));
      }
      case 114: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isSigned(); return mkResult(QJsonValue(retval));
      }
      case 115: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isText(); return mkResult(QJsonValue(retval));
      }
      case 116: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isUTF8Text(); return mkResult(QJsonValue(retval));
      }
      case 117: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isUnicodeText(); return mkResult(QJsonValue(retval));
      }
      case 118: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        bool retval = obj->isVerbose(); return mkResult(QJsonValue(retval));
      }
      case 119: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        bool retval = obj->isZeroFilled(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 120: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString retval = obj->lowerCase(arg0); return mkResult(QJsonValue(retval));
      }
      case 121: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        quint8 retval = obj->readByte(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 122: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        bool arg2 = args[2].toBool();
        QList<QVariant> retval = obj->readBytes(arg0, arg1, arg2);
        QJsonArray ja = QJsonArray::fromVariantList(retval);
        return mkResult(QJsonValue(ja));
      }
      case 123: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        quint32 retval = obj->readDword(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 124: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        quint64 retval = obj->readQword(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 125: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint16 retval = obj->readSByte(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 126: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint32 retval = obj->readSDword(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 127: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 retval = obj->readSQword(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 128: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint16 retval = obj->readSWord(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 129: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        quint16 retval = obj->readWord(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 130: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        QString retval = obj->read_UUID(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 131: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        QString retval = obj->read_UUID_bytes(arg0); return mkResult(QJsonValue(retval));
      }
      case 132: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->read_ansiString(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 133: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint16 retval = obj->read_bcd_uint16(arg0, arg1); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 134: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint16 retval = obj->read_bcd_uint32(arg0, arg1); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 135: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint16 retval = obj->read_bcd_uint64(arg0, arg1); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 136: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        quint8 retval = obj->read_bcd_uint8(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 137: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString arg2 = args[2].toString();
        QString retval = obj->read_codePageString(arg0, arg1, arg2); return mkResult(QJsonValue(retval));
      }
      case 138: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        double retval = obj->read_double(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 139: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        float retval = obj->read_float(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 140: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        float retval = obj->read_float16(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 141: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        float retval = obj->read_float32(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 142: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        double retval = obj->read_float64(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 143: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        qint16 retval = obj->read_int16(arg0, arg1); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 144: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        qint32 retval = obj->read_int24(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 145: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        qint32 retval = obj->read_int32(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 146: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        qint64 retval = obj->read_int64(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 147: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint16 retval = obj->read_int8(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 148: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        QString retval = obj->read_ucsdString(arg0); return mkResult(QJsonValue(retval));
      }
      case 149: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint16 retval = obj->read_uint16(arg0, arg1); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 150: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint32 retval = obj->read_uint24(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 151: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint32 retval = obj->read_uint32(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 152: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        bool arg1 = args[1].toBool();
        quint64 retval = obj->read_uint64(arg0, arg1); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 153: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        quint8 retval = obj->read_uint8(arg0); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 154: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->read_unicodeString(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 155: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        qint64 arg0 = args[0].toVariant().toLongLong();
        qint64 arg1 = args[1].toVariant().toLongLong();
        QString retval = obj->read_utf8String(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 156: { 
        auto* obj = session->script();
        if (!obj) return nullptr;

        qint64 retval = obj->startTiming(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 157: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->swapBytes(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 158: { 
        auto* obj = session->script();
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString retval = obj->upperCase(arg0); return mkResult(QJsonValue(retval));
      }
      case 159: { 
        auto* obj = static_cast<DEX_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getMapItemsHash(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 160: { 
        auto* obj = static_cast<DEX_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isDexItemStringPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 161: { 
        auto* obj = static_cast<DEX_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isDexStringPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 162: { 
        auto* obj = static_cast<DEX_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isStringPoolSorted(); return mkResult(QJsonValue(retval));
      }
      case 163: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getElfHeader_ehsize(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 164: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint64 retval = obj->getElfHeader_entry(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 165: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getElfHeader_flags(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 166: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getElfHeader_machine(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 167: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getElfHeader_phentsize(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 168: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getElfHeader_phnum(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 169: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint64 retval = obj->getElfHeader_phoff(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 170: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getElfHeader_shentsize(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 171: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getElfHeader_shnum(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 172: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint64 retval = obj->getElfHeader_shoff(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 173: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getElfHeader_shstrndx(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 174: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getElfHeader_type(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 175: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getElfHeader_version(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 176: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getGeneralOptions(); return mkResult(QJsonValue(retval));
      }
      case 177: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getNumberOfPrograms(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 178: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getNumberOfSections(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 179: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint64 retval = obj->getProgramFileOffset(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 180: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint64 retval = obj->getProgramFileSize(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 181: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getRunPath(); return mkResult(QJsonValue(retval));
      }
      case 182: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint64 retval = obj->getSectionFileOffset(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 183: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint64 retval = obj->getSectionFileSize(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 184: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint32 retval = obj->getSectionNumber(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 185: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isLibraryPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 186: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isNotePresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 187: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isSectionNamePresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 188: { 
        auto* obj = static_cast<ELF_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString arg1 = args[1].toString();
        bool retval = obj->isStringInTablePresent(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 189: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getAbstractFileIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 190: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getApplicationIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 191: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getBibliographicFileIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 192: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getCopyrightFileIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 193: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getDataPreparerIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 194: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getPublisherIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 195: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getSystemIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 196: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getVolumeIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 197: { 
        auto* obj = static_cast<ISO9660_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getVolumeSetIdentifier(); return mkResult(QJsonValue(retval));
      }
      case 198: { 
        auto* obj = static_cast<JAR_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getManifest(); return mkResult(QJsonValue(retval));
      }
      case 199: { 
        auto* obj = static_cast<JAR_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString retval = obj->getManifestRecord(arg0); return mkResult(QJsonValue(retval));
      }
      case 200: { 
        auto* obj = static_cast<Jpeg_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getComment(); return mkResult(QJsonValue(retval));
      }
      case 201: { 
        auto* obj = static_cast<Jpeg_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getDqtMD5(); return mkResult(QJsonValue(retval));
      }
      case 202: { 
        auto* obj = static_cast<Jpeg_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getExifCameraName(); return mkResult(QJsonValue(retval));
      }
      case 203: { 
        auto* obj = static_cast<Jpeg_Script*>(session->script());
        if (!obj) return nullptr;
        qint32 arg0 = args[0].toVariant().toInt();
        bool retval = obj->isChunkPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 204: { 
        auto* obj = static_cast<Jpeg_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isExifPresent(); return mkResult(QJsonValue(retval));
      }
      case 205: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->getCommandId(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 206: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getGeneralOptions(); return mkResult(QJsonValue(retval));
      }
      case 207: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        quint32 retval = obj->getLibraryCurrentVersion(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 208: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getNumberOfCommands(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 209: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getNumberOfSections(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 210: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getNumberOfSegments(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 211: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint64 retval = obj->getSectionFileOffset(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 212: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint64 retval = obj->getSectionFileSize(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 213: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint32 retval = obj->getSectionNumber(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 214: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        bool retval = obj->isCommandPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 215: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isLibraryPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 216: { 
        auto* obj = static_cast<MACH_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isSectionNamePresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 217: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        qint64 retval = obj->getDosStubOffset(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 218: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        qint64 retval = obj->getDosStubSize(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 219: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getNumberOfRichIDs(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 220: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;
        qint32 arg0 = args[0].toVariant().toInt();
        quint32 retval = obj->getRichCount(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 221: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;
        qint32 arg0 = args[0].toVariant().toInt();
        quint32 retval = obj->getRichID(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 222: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;
        qint32 arg0 = args[0].toVariant().toInt();
        quint32 retval = obj->getRichVersion(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 223: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isDosStubPresent(); return mkResult(QJsonValue(retval));
      }
      case 224: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isLE(); return mkResult(QJsonValue(retval));
      }
      case 225: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isLX(); return mkResult(QJsonValue(retval));
      }
      case 226: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isNE(); return mkResult(QJsonValue(retval));
      }
      case 227: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isPE(); return mkResult(QJsonValue(retval));
      }
      case 228: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isRichSignaturePresent(); return mkResult(QJsonValue(retval));
      }
      case 229: { 
        auto* obj = static_cast<MSDOS_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        bool retval = obj->isRichVersionPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 230: { 
        auto* obj = static_cast<NPM_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getPackageJson(); return mkResult(QJsonValue(retval));
      }
      case 231: { 
        auto* obj = static_cast<NPM_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString retval = obj->getPackageJsonRecord(arg0); return mkResult(QJsonValue(retval));
      }
      case 232: { 
        auto* obj = static_cast<PDF_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getHeaderCommentAsHex(); return mkResult(QJsonValue(retval));
      }
      case 233: { 
        auto* obj = static_cast<PDF_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QList<QVariant> retval = obj->getStringValuesByKey(arg0);
        QJsonArray ja = QJsonArray::fromVariantList(retval);
        return mkResult(QJsonValue(ja));
      }
      case 234: { 
        auto* obj = static_cast<PDF_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QList<QVariant> retval = obj->getValuesByKey(arg0);
        QJsonArray ja = QJsonArray::fromVariantList(retval);
        return mkResult(QJsonValue(ja));
      }
      case 235: { 
        auto* obj = static_cast<PDF_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isValuesHexByKey(arg0); return mkResult(QJsonValue(retval));
      }
      case 236: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->_isSectionNamePresentExp(arg0); return mkResult(QJsonValue(retval));
      }
      case 237: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint64 retval = obj->calculateSizeOfHeaders(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 238: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint64 arg1 = args[1].toVariant().toLongLong();
        bool retval = obj->compareEP_NET(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 239: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint64 retval = obj->findSignatureInBlob_NET(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 240: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getCompilerVersion(); return mkResult(QJsonValue(retval));
      }
      case 241: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        qint64 retval = obj->getDebugDataOffset(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 242: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        qint64 retval = obj->getDebugDataSize(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 243: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        QString retval = obj->getDebugDataType(arg0); return mkResult(QJsonValue(retval));
      }
      case 244: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getEntryPointSection(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 245: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        QString retval = obj->getExportFunctionName(arg0); return mkResult(QJsonValue(retval));
      }
      case 246: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        QString retval = obj->getExportNameByNumber(arg0); return mkResult(QJsonValue(retval));
      }
      case 247: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getExportSection(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 248: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getFileVersion(); return mkResult(QJsonValue(retval));
      }
      case 249: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getFileVersionMS(); return mkResult(QJsonValue(retval));
      }
      case 250: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getGeneralOptions(); return mkResult(QJsonValue(retval));
      }
      case 251: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        quint64 retval = obj->getImageFileHeader(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 252: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        quint64 retval = obj->getImageOptionalHeader(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 253: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 arg1 = args[1].toVariant().toUInt();
        QString retval = obj->getImportFunctionName(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 254: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getImportHash32(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 255: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        quint64 retval = obj->getImportHash64(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 256: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        QString retval = obj->getImportLibraryName(arg0); return mkResult(QJsonValue(retval));
      }
      case 257: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getImportSection(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 258: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        quint8 retval = obj->getMajorLinkerVersion(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 259: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getManifest(); return mkResult(QJsonValue(retval));
      }
      case 260: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        quint8 retval = obj->getMinorLinkerVersion(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 261: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getNETVersion(); return mkResult(QJsonValue(retval));
      }
      case 262: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getNetAssemblyName(); return mkResult(QJsonValue(retval));
      }
      case 263: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        QString retval = obj->getNetModuleName(); return mkResult(QJsonValue(retval));
      }
      case 264: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getNumberOfDebugDataRecords(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 265: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getNumberOfExportFunctions(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 266: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getNumberOfExports(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 267: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        qint32 retval = obj->getNumberOfImportThunks(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 268: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getNumberOfImports(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 269: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getNumberOfResources(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 270: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        quint16 retval = obj->getNumberOfSections(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 271: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString retval = obj->getPEFileVersion(arg0); return mkResult(QJsonValue(retval));
      }
      case 272: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getRelocsSection(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 273: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->getResourceIdByNumber(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 274: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        QString retval = obj->getResourceNameByNumber(arg0); return mkResult(QJsonValue(retval));
      }
      case 275: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint64 retval = obj->getResourceNameOffset(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 276: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        qint64 retval = obj->getResourceOffsetByNumber(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 277: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getResourceSection(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 278: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        qint64 retval = obj->getResourceSizeByNumber(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 279: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->getResourceTypeByNumber(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 280: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->getSectionCharacteristics(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 281: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->getSectionFileOffset(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 282: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->getSectionFileSize(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 283: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        QString retval = obj->getSectionName(arg0); return mkResult(QJsonValue(retval));
      }
      case 284: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString arg1 = args[1].toString();
        QString retval = obj->getSectionNameCollision(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 285: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint32 retval = obj->getSectionNumber(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 286: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        qint32 retval = obj->getSectionNumberExp(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 287: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->getSectionVirtualAddress(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 288: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        quint32 retval = obj->getSectionVirtualSize(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 289: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getSizeOfCode(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 290: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getSizeOfUninitializedData(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 291: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getTLSSection(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 292: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString retval = obj->getVersionStringInfo(arg0); return mkResult(QJsonValue(retval));
      }
      case 293: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isConsole(); return mkResult(QJsonValue(retval));
      }
      case 294: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isDll(); return mkResult(QJsonValue(retval));
      }
      case 295: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isDriver(); return mkResult(QJsonValue(retval));
      }
      case 296: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isExportFunctionPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 297: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isExportPresent(); return mkResult(QJsonValue(retval));
      }
      case 298: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isFunctionPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 299: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        qint32 arg0 = args[0].toVariant().toInt();
        quint32 arg1 = args[1].toVariant().toUInt();
        bool retval = obj->isImportPositionHashPresent(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 300: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isImportPresent(); return mkResult(QJsonValue(retval));
      }
      case 301: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString arg1 = args[1].toString();
        bool retval = obj->isLibraryFunctionPresent(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 302: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool arg1 = args[1].toBool();
        bool retval = obj->isLibraryPresent(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 303: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isNET(); return mkResult(QJsonValue(retval));
      }
      case 304: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isNETStringPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 305: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isNETUnicodeStringPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 306: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isNet(); return mkResult(QJsonValue(retval));
      }
      case 307: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString arg1 = args[1].toString();
        QString arg2 = args[2].toString();
        bool retval = obj->isNetFieldPresent(arg0, arg1, arg2); return mkResult(QJsonValue(retval));
      }
      case 308: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isNetGlobalCctorPresent(); return mkResult(QJsonValue(retval));
      }
      case 309: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString arg1 = args[1].toString();
        QString arg2 = args[2].toString();
        bool retval = obj->isNetMethodPresent(arg0, arg1, arg2); return mkResult(QJsonValue(retval));
      }
      case 310: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isNetObjectPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 311: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        QString arg1 = args[1].toString();
        bool retval = obj->isNetTypePresent(arg0, arg1); return mkResult(QJsonValue(retval));
      }
      case 312: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isNetUStringPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 313: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isPEPlus(); return mkResult(QJsonValue(retval));
      }
      case 314: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        quint32 arg0 = args[0].toVariant().toUInt();
        bool retval = obj->isResourceGroupIdPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 315: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isResourceGroupNamePresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 316: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isResourceNamePresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 317: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isResourcesPresent(); return mkResult(QJsonValue(retval));
      }
      case 318: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isSectionNamePresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 319: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isSignatureInBlobPresent_NET(arg0); return mkResult(QJsonValue(retval));
      }
      case 320: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isSignedFile(); return mkResult(QJsonValue(retval));
      }
      case 321: { 
        auto* obj = static_cast<PE_Script*>(session->script());
        if (!obj) return nullptr;

        bool retval = obj->isTLSPresent(); return mkResult(QJsonValue(retval));
      }
      case 322: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;

        quint8 retval = obj->getBitDepth(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 323: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;
        qint32 arg0 = args[0].toVariant().toInt();
        QString retval = obj->getChunkName(arg0); return mkResult(QJsonValue(retval));
      }
      case 324: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;
        qint32 arg0 = args[0].toVariant().toInt();
        quint32 retval = obj->getChunkSize(arg0); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 325: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;

        quint8 retval = obj->getColorType(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 326: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;

        quint8 retval = obj->getCompression(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 327: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;

        quint8 retval = obj->getFilter(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 328: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getHeight(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 329: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;

        quint8 retval = obj->getInterlace(); return mkResult(QJsonValue(static_cast<int>(retval)));
      }
      case 330: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;

        qint32 retval = obj->getNumberOfChunks(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 331: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;

        quint32 retval = obj->getWidth(); return mkResult(QJsonValue(static_cast<double>(retval)));
      }
      case 332: { 
        auto* obj = static_cast<PNG_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isChunkPresent(arg0); return mkResult(QJsonValue(retval));
      }
      case 333: { 
        auto* obj = static_cast<PYC_Script*>(session->script());
        if (!obj) return nullptr;
        QString arg0 = args[0].toString();
        bool retval = obj->isConstPresent(arg0); return mkResult(QJsonValue(retval));
      }
      default:
        return nullptr;
    }
}
