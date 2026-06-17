import type {
  DecompWorkerRequest,
  DecompWorkerReply,
  DecompRegion,
  DecompFunction,
  DecompCallTarget,
} from "./protocol";

export interface DecompileOutput {
  code: string;
  calls: DecompCallTarget[];
}

const SPEC_BASE_URL = "/specs/";
const SPEC_MANIFEST_URL = "/specs/manifest.json";

interface Pending {
  resolve(value: DecompWorkerReply): void;
  reject(reason: unknown): void;
}

export interface OpenOptions {
  arch: string;
  languageId: string;
  regions: DecompRegion[];
  symbols: [number, string][];
  imports: [number, string][];
  readonly: [number, number][];
  strings: [number, number][];
  widestrings: [number, number][];
  functions: DecompFunction[];
  prototypes: string;
}

export class DecompilerClient {
  private worker: Worker;
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private inits = new Map<string, Promise<void>>();

  constructor() {
    this.worker = new Worker(new URL("./worker.ts", import.meta.url), {
      type: "module",
      name: "die-decompiler-worker",
    });
    this.worker.addEventListener("message", (ev: MessageEvent<DecompWorkerReply>) => {
      const reply = ev.data;
      const p = this.pending.get(reply.id);
      if (!p) return;
      this.pending.delete(reply.id);
      p.resolve(reply);
    });
    this.worker.addEventListener("error", (ev) => {
      const err = new Error(ev.message || "decompiler worker crashed");
      for (const p of this.pending.values()) p.reject(err);
      this.pending.clear();
    });
  }

  private ensureInit(arch: string): Promise<void> {
    let p = this.inits.get(arch);
    if (!p) {
      p = this.send({ cmd: "init", specBaseUrl: SPEC_BASE_URL, manifestUrl: SPEC_MANIFEST_URL, arch })
        .then(() => undefined);
      this.inits.set(arch, p);
    }
    return p;
  }

  async open(opts: OpenOptions): Promise<DecompilerSession> {
    await this.ensureInit(opts.arch);
    const transfer = opts.regions.map((r) => r.bytes);
    const reply = await this.send(
      {
        cmd: "open",
        languageId: opts.languageId,
        regions: opts.regions,
        symbols: opts.symbols,
        imports: opts.imports,
        readonly: opts.readonly,
        strings: opts.strings,
        widestrings: opts.widestrings,
        prototypes: opts.prototypes,
      },
      transfer,
    );
    if (reply.ok !== true || reply.sessionId == null) throw new Error("open: no session id");
    return new DecompilerSession(this, reply.sessionId);
  }

  decompileSession(sessionId: number, address: number, name?: string): Promise<DecompileOutput> {
    return this.send({ cmd: "decompile", sessionId, address, name }).then((r) => {
      if (r.ok !== true || r.code == null) throw new Error("decompile: no code");
      return { code: r.code, calls: r.calls ?? [] };
    });
  }

  callTargetsSession(sessionId: number, address: number): Promise<DecompCallTarget[]> {
    return this.send({ cmd: "callTargets", sessionId, address }).then((r) => {
      if (r.ok !== true) throw new Error("callTargets failed");
      return r.calls ?? [];
    });
  }

  closeSession(sessionId: number): Promise<void> {
    return this.send({ cmd: "close", sessionId }).then(() => undefined);
  }

  private send(
    msg: { cmd: DecompWorkerRequest["cmd"] } & Record<string, unknown>,
    transfer: Transferable[] = [],
  ): Promise<DecompWorkerReply & { ok: true }> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, {
        resolve: (v) => (v.ok ? resolve(v) : reject(new Error(v.error))),
        reject,
      });
      this.worker.postMessage({ ...msg, id }, transfer);
    });
  }
}

export class DecompilerSession {
  private closed = false;
  constructor(
    private client: DecompilerClient,
    public readonly sessionId: number,
  ) {}

  decompile(address: number, name?: string): Promise<DecompileOutput> {
    if (this.closed) return Promise.reject(new Error("session closed"));
    return this.client.decompileSession(this.sessionId, address, name);
  }

  callTargets(address: number): Promise<DecompCallTarget[]> {
    if (this.closed) return Promise.reject(new Error("session closed"));
    return this.client.callTargetsSession(this.sessionId, address);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.client.closeSession(this.sessionId);
  }
}

let singleton: DecompilerClient | null = null;

export function getDecompilerClient(): DecompilerClient {
  if (!singleton) singleton = new DecompilerClient();
  return singleton;
}
