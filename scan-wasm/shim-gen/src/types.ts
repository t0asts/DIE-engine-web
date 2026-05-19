
export interface CppParam {
  cppType: string;          
  name: string;             
  defaultValue?: string;    
}

export interface CppMethod {
  className: string;        
  jsClass: string;          
  parentJsClass: string | null; 
  name: string;             
  cppReturn: string;        
  params: CppParam[];
  isHotPath: boolean;       
  methodId: number;         
}

export interface BindingManifest {
  version: number;
  generatedFrom: { repo: string; commit?: string; headers: string[] };
  hotPathExports: string[];   
  
  parents: Record<string, string | null>;
  classes: {
    name: string;             
    cppClass: string;
    methods: {
      name: string;
      methodId: number;
      jsReturn: string;
      jsParams: { name: string; type: string; optional: boolean }[];
      isHotPath: boolean;
      hotPathExport?: string; 
    }[];
  }[];
}

export function jsTypeOf(cppType: string): string {
  
  const t = cppType
    .replace(/\bconst\b/g, "")
    .replace(/[&*]/g, "")
    .trim();

  switch (t) {
    case "void":
      return "void";
    case "bool":
      return "boolean";
    case "qint8":
    case "qint16":
    case "qint32":
    case "quint8":
    case "quint16":
    case "quint32":
    case "int":
    case "unsigned":
    case "unsigned int":
    case "uint":
    case "float":
    case "double":
      return "number";
    case "qint64":
    case "quint64":
    case "qlonglong":
    case "qulonglong":
      
      return "number";
    case "QString":
      return "string";
    case "QByteArray":
      return "Uint8Array";
    case "QStringList":
    case "QList<QString>":
      return "string[]";
    case "QList<QVariant>":
      return "unknown[]";
    case "QVariant":
      return "unknown";
  }

  const list = t.match(/^Q(?:List|Set|Vector)<(.+)>$/);
  if (list) return `${jsTypeOf(list[1]!)}[]`;

  const map = t.match(/^QMap<(.+),(.+)>$/);
  if (map) {
    const k = jsTypeOf(map[1]!.trim());
    const v = jsTypeOf(map[2]!.trim());
    return `Record<${k === "number" ? "number" : "string"}, ${v}>`;
  }

  return "unknown";
}

const HOT_PATH_NAMES = new Set([
  "readByte",   "readSByte", "readWord",  "readSWord",
  "readDword",  "readSDword","readQword", "readSQword",
  "read_uint8", "read_int8",
  "read_uint16","read_int16",
  "read_uint24","read_int24",
  "read_uint32","read_int32",
  "read_uint64","read_int64",
  "read_float", "read_double",
  "read_float16","read_float32","read_float64",
  "U8","I8","U16","I16","U24","I24","U32","I32","U64","I64","F16","F32","F64",
  "compare", "compareEP",
  "findSignature", "fSig",
  "findString", "fStr",
  "findByte", "findWord", "findDword",
  "isSignaturePresent",
  "getSize", "Sz",
]);

export function isHotPath(method: { name: string; cppReturn: string; params: CppParam[] }): boolean {
  return HOT_PATH_NAMES.has(method.name);
}
