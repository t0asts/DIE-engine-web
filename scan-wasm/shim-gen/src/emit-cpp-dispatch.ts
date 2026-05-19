
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { CppMethod, CppParam } from "./types.ts";

interface DispatchOptions {
  outPath: string;            
}

const ARG_DECODERS: Record<string, (idx: number, name: string) => string> = {
  "bool":      (i, n) => `bool ${n} = args[${i}].toBool();`,
  "qint8":     (i, n) => `qint8 ${n} = static_cast<qint8>(args[${i}].toInt());`,
  "quint8":    (i, n) => `quint8 ${n} = static_cast<quint8>(args[${i}].toInt());`,
  "qint16":    (i, n) => `qint16 ${n} = static_cast<qint16>(args[${i}].toInt());`,
  "quint16":   (i, n) => `quint16 ${n} = static_cast<quint16>(args[${i}].toInt());`,
  "qint32":    (i, n) => `qint32 ${n} = args[${i}].toVariant().toInt();`,
  "quint32":   (i, n) => `quint32 ${n} = args[${i}].toVariant().toUInt();`,
  "qint64":    (i, n) => `qint64 ${n} = args[${i}].toVariant().toLongLong();`,
  "quint64":   (i, n) => `quint64 ${n} = args[${i}].toVariant().toULongLong();`,
  "int":       (i, n) => `int ${n} = args[${i}].toInt();`,
  "double":    (i, n) => `double ${n} = args[${i}].toDouble();`,
  "float":     (i, n) => `float ${n} = static_cast<float>(args[${i}].toDouble());`,
  "QString":   (i, n) => `QString ${n} = args[${i}].toString();`,
};

const RET_ENCODERS: Record<string, (expr: string) => string> = {
  "void":      ()    => `Q_UNUSED(retval); return mkResult(QJsonValue());`,
  "bool":      e     => `bool retval = ${e}; return mkResult(QJsonValue(retval));`,
  "qint8":     e     => `qint8 retval = ${e}; return mkResult(QJsonValue(static_cast<int>(retval)));`,
  "quint8":    e     => `quint8 retval = ${e}; return mkResult(QJsonValue(static_cast<int>(retval)));`,
  "qint16":    e     => `qint16 retval = ${e}; return mkResult(QJsonValue(static_cast<int>(retval)));`,
  "quint16":   e     => `quint16 retval = ${e}; return mkResult(QJsonValue(static_cast<int>(retval)));`,
  "qint32":    e     => `qint32 retval = ${e}; return mkResult(QJsonValue(static_cast<double>(retval)));`,
  "quint32":   e     => `quint32 retval = ${e}; return mkResult(QJsonValue(static_cast<double>(retval)));`,
  "qint64":    e     => `qint64 retval = ${e}; return mkResult(QJsonValue(static_cast<double>(retval)));`,
  "quint64":   e     => `quint64 retval = ${e}; return mkResult(QJsonValue(static_cast<double>(retval)));`,
  "int":       e     => `int retval = ${e}; return mkResult(QJsonValue(retval));`,
  "double":    e     => `double retval = ${e}; return mkResult(QJsonValue(retval));`,
  "float":     e     => `float retval = ${e}; return mkResult(QJsonValue(static_cast<double>(retval)));`,
  "QString":   e     => `QString retval = ${e}; return mkResult(QJsonValue(retval));`,
};

function normalizeType(cppType: string): string {
  return cppType
    .replace(/\bconst\b/g, "")
    .replace(/[&*]/g, "")
    .trim();
}

function listInnerType(t: string): string | null {
  const m = t.match(/^Q(?:List|Set|Vector|StringList)<(.+)>$/);
  if (m) return m[1]!.trim();
  if (t === "QStringList") return "QString";
  return null;
}

function decodeArg(p: CppParam, idx: number): string | null {
  const t = normalizeType(p.cppType);
  const safe = `arg${idx}`;
  const dec = ARG_DECODERS[t];
  if (dec) return dec(idx, safe);

  const inner = listInnerType(t);
  if (inner === "QString") {
    return `QStringList ${safe}; { auto a = args[${idx}].toArray(); for (auto v : a) ${safe}.append(v.toString()); }`;
  }
  if (inner === "QVariant") {
    return `QList<QVariant> ${safe} = args[${idx}].toArray().toVariantList();`;
  }

  return null;
}

function encodeReturn(cppReturn: string, callExpr: string): string {
  const t = normalizeType(cppReturn);
  const enc = RET_ENCODERS[t];
  if (enc) return enc(callExpr);

  const inner = listInnerType(t);
  if (inner === "QString") {
    return `QStringList retval = ${callExpr};
        QJsonArray ja; for (const QString& s : retval) ja.append(s);
        return mkResult(QJsonValue(ja));`;
  }
  if (inner === "QVariant") {
    return `QList<QVariant> retval = ${callExpr};
        QJsonArray ja = QJsonArray::fromVariantList(retval);
        return mkResult(QJsonValue(ja));`;
  }
  if (t === "QByteArray") {
    return `QByteArray retval = ${callExpr};
        return mkResult(QJsonValue(QString::fromLatin1(retval.toBase64())));`;
  }

  return `Q_UNUSED(session);
        return mkResult(QJsonValue());`;
}

function caseBody(m: CppMethod): string {
  
  const cppClass = m.className;
  const cast = cppClass === "Binary_Script"
    ? `auto* obj = session->script();`
    : `auto* obj = static_cast<${cppClass}*>(session->script());`;

  const argDecls: string[] = [];
  let unsupported = false;
  m.params.forEach((p, i) => {
    const line = decodeArg(p, i);
    if (line === null) {
      unsupported = true;
    } else {
      argDecls.push("        " + line);
    }
  });

  if (unsupported) {
    return `      case ${m.methodId}: {
        return mkResult(QJsonValue());
      }`;
  }

  const argRefs = m.params.map((_, i) => `arg${i}`).join(", ");
  const callExpr = `obj->${m.name}(${argRefs})`;

  const ret = encodeReturn(m.cppReturn, callExpr);

  return `      case ${m.methodId}: {
        ${cast}
        if (!obj) return nullptr;
${argDecls.join("\n")}
        ${ret}
      }`;
}

function emit(methods: CppMethod[]): string {
  const sorted = [...methods].sort((a, b) => a.methodId - b.methodId);

  const includes = new Set<string>();

  const formatHeaders = [
    "xbinary.h", "xformats.h",
    "xpe.h", "xelf.h", "xmach.h", "xmachofat.h",
    "xne.h", "xle.h", "xmsdos.h", "xcom.h",
    "xdex.h", "xpdf.h", "xcfbf.h",
    "xjpeg.h", "xpng.h",
    "xrar.h", "xzip.h", "xjar.h",
    "xapk.h", "xipa.h", "xnpm.h",
    "xiso9660.h",
    "xamigahunk.h", "xatarist.h",
    "xjavaclass.h", "xpyc.h", "xdos16.h",
  ];
  for (const h of formatHeaders) includes.add(`#include "${h}"`);

  for (const m of sorted) {
    const lower = m.className.toLowerCase();
    includes.add(`#include "${lower}.h"`);
  }

  const header = `#include "Session.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QString>
#include <QStringList>
#include <QVariant>

#include <cstdlib>
#include <cstring>

${[...includes].sort().join("\n")}

namespace {

char* mkResult(const QJsonValue& v) {
    QJsonObject env;
    env["result"] = v;
    QByteArray bytes = QJsonDocument(env).toJson(QJsonDocument::Compact);
    char* out = static_cast<char*>(std::malloc(static_cast<size_t>(bytes.size()) + 1));
    if (!out) return nullptr;
    std::memcpy(out, bytes.constData(), static_cast<size_t>(bytes.size()));
    out[bytes.size()] = '\\0';
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
`;

  const cases = sorted.map(caseBody).join("\n");

  const footer = `
      default:
        return nullptr;
    }
}
`;

  return header + cases + footer;
}

export function emitCppDispatch(methods: CppMethod[], opts: DispatchOptions): void {
  mkdirSync(dirname(opts.outPath), { recursive: true });
  writeFileSync(opts.outPath, emit(methods));
}
