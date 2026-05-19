
export type ScanOptions = {
  deepScan?: boolean;
  heuristicScan?: boolean;
  aggressiveScan?: boolean;
  recursiveScan?: boolean;
  overlayScan?: boolean;
  resourcesScan?: boolean;
  archivesScan?: boolean;
  verbose?: boolean;
  stringsMinLen?: number;    
};

export type FormatId =
  | "Binary" | "PE" | "ELF" | "MACH" | "MACHOFAT" | "MSDOS" | "COM"
  | "NE" | "LE" | "LX" | "DEX" | "PDF" | "CFBF" | "Jpeg" | "PNG"
  | "RAR" | "ZIP" | "JAR" | "APK" | "IPA" | "NPM" | "ISO9660"
  | "Amiga" | "AtariST" | "JavaClass" | "PYC" | "DOS16M" | "DOS4G"
  | "Archive" | "Image";

export interface FileInfo {
  size: number;
  primaryFormat: string;
  allFormats: string[];
}

export interface Hashes {
  md5: string;
  sha1: string;
  sha256: string;
}

export interface EntropyPoint {
  offset: number;
  value: number;
}

export interface ScanRecord {
  type: string;             
  name: string;             
  version?: string;
  options?: string;
  language?: string;
  description?: string;
}

export interface ScriptOutcome {
  path: string;
  ok: boolean;
  durationMs: number;
  records: number;
  error?: string;
  logs?: string[];
}

export interface DebugLog {
  fileName?: string;
  fileSize: number;
  jsClass: string;                  
  scriptsAttempted: number;
  scriptsSucceeded: number;
  scriptsFailed: number;
  scriptOutcomes: ScriptOutcome[];  
}

export interface MemoryRecord {
  name: string;
  offset: number;
  address: number;
  size: number;
  index: number;
  isVirtual: boolean;
  isInvisible: boolean;
  filePart: number;
}

export interface MemoryMap {
  moduleAddress: number;
  imageSize: number;
  binarySize: number;
  entryPoint: number;
  fileType: string;
  arch: string;
  mode: string;
  endian: "little" | "big";
  records: MemoryRecord[];
}

export interface StringEntry {
  offset: number;
  length: number;
  encoding: "ascii" | "utf16le";
  text: string;
}

export interface ArchiveEntry {
  name: string;
  isDir: boolean;
  size: number;             
  compressedSize: number;
  method: string;           
  crc32: number;
  date?: string;            
  encrypted: boolean;
}

export interface ArchiveListing {
  kind: string;             
  entries: ArchiveEntry[];
  totalEntries: number;     
  totalSize: number;        
  totalCompressedSize: number;
  truncated: boolean;       
  comment?: string;
  note?: string;            
}

export interface ExtractEntry {
  offset: number;
  size: number;
  type: string;              
  name?: string;
  ext?: string;
  string?: string;           
}

export interface StructNode {
  name: string;
  value?: string;            
  children?: StructNode[];
}

export interface DisasmInsn {
  address: number;
  size: number;
  hex: string;               
  mnemonic: string;          
  operands: string;
  branch?: number;           
}

export type DisasmMode = "auto" | "arm" | "thumb" | "cortexm";

export interface DisasmResult {
  mode: string;              
                             
  insns: DisasmInsn[];
}

export interface SymbolEntry {
  name: string;
  demangled?: string;        
  kind: "import" | "export" | "symbol";
  address?: number;          
  size?: number;
  type?: string;             
  bind?: string;             
  section?: string;          
  library?: string;          
  ordinal?: number;          
}

export interface YaraStringMatch {
  id: string;                
  offset: number;            
  dataHex: string;           
  truncated?: boolean;       
}
export interface YaraMatch {
  rule: string;
  namespace: string;         
  tags?: string[];
  meta?: Record<string, string | number | boolean>;
  strings?: YaraStringMatch[];
}
export interface YaraCompileError {
  level: "error" | "warning";
  line: number;              
  message: string;
  unit?: string;             
}

export interface YaraRuleUnit {
  ns: string;
  src: string;
}
export interface YaraScanResult {
  ok: boolean;
  errors?: YaraCompileError[];
  matches?: YaraMatch[];
  timeout?: boolean;         
  truncated?: boolean;       
  scanError?: number;        
}

export interface ModuleLog {
  module: string;
  ok: boolean;
  durationMs: number;
  note?: string;             
  error?: string;            
  detail?: string;           
}

export interface ScanResult {
  fileInfo: FileInfo;
  hashes: Hashes;
  entropy: EntropyPoint[];
  records: ScanRecord[];
  errors: string[];
  debugLog: DebugLog;        
  moduleLogs: ModuleLog[];
  memoryMap: MemoryMap | null;
  strings: StringEntry[];
  archive: ArchiveListing | null;
  structure: StructNode[];
  symbols: SymbolEntry[];
  extracted: ExtractEntry[]; 
  mime: string[];            
  disasmAvailable: boolean;  
                             
  durationMs: number;
}

export type WorkerRequest =
  | InitRequest
  | ScanRequest
  | OpenSessionRequest
  | InvokeBindingRequest
  | InvokeHotRequest
  | CloseSessionRequest
  | DemangleRequest
  | DisasmRequest
  | YaraScanRequest
  | ExtractArchiveEntryRequest;

export interface ExtractArchiveEntryRequest {
  id: number;
  cmd: "extractArchiveEntry";
  bytes: ArrayBuffer;        
  entryName: string;
}

export interface YaraScanRequest {
  id: number;
  cmd: "yaraScan";
  bytes: ArrayBuffer;        
  units: YaraRuleUnit[];     
}

export interface DisasmRequest {
  id: number;
  cmd: "disasm";
  bytes: ArrayBuffer;        
  address: number;           
  count: number;             
  mode?: DisasmMode;         
}

export interface DemangleRequest {
  id: number;
  cmd: "demangle";
  name: string;
}

export interface InitRequest {
  id: number;
  cmd: "init";
  signaturesUrl: string;     
  manifestUrl: string;       
}

export interface ScanRequest {
  id: number;
  cmd: "scan";
  bytes: ArrayBuffer;        
  options: ScanOptions;
}

export interface OpenSessionRequest {
  id: number;
  cmd: "openSession";
  bytes: ArrayBuffer;        
  optionsJson?: string;      
}

export interface InvokeBindingRequest {
  id: number;
  cmd: "invokeBinding";
  sessionId: number;
  methodId: number;
  args: unknown[];
}

export interface InvokeHotRequest {
  id: number;
  cmd: "invokeHot";
  sessionId: number;
  exportName: string;
  args: unknown[];
}

export interface CloseSessionRequest {
  id: number;
  cmd: "closeSession";
  sessionId: number;
}

export type WorkerReply =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: string };

export interface OpenSessionReply {
  sessionId: number;
  jsClass: string;           
  fileInfo: FileInfo;
}
