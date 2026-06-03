export interface DecompRegion {
  vaddr: number;
  bytes: ArrayBuffer;
}

export interface DecompFunction {
  addr: number;
  name: string;
  kind: string;
}

export interface DecompCallTarget {
  addr: number;
  name?: string;
}

export type DecompWorkerRequest =
  | DecompInitRequest
  | DecompOpenRequest
  | DecompileRequest
  | DecompCallTargetsRequest
  | DecompCloseRequest;

export interface DecompInitRequest {
  id: number;
  cmd: "init";
  specBaseUrl: string;
  manifestUrl: string;
  arch: string;
}

export interface DecompOpenRequest {
  id: number;
  cmd: "open";
  languageId: string;
  regions: DecompRegion[];
  symbols: [number, string][];
  readonly: [number, number][];
  strings: [number, number][];
}

export interface DecompileRequest {
  id: number;
  cmd: "decompile";
  sessionId: number;
  address: number;
  name?: string;
}

export interface DecompCallTargetsRequest {
  id: number;
  cmd: "callTargets";
  sessionId: number;
  address: number;
}

export interface DecompCloseRequest {
  id: number;
  cmd: "close";
  sessionId: number;
}

export type DecompWorkerReply =
  | { id: number; ok: true; sessionId?: number; code?: string; calls?: DecompCallTarget[] }
  | { id: number; ok: false; error: string };
