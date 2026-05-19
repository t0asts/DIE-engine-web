
import type {
  WorkerRequest,
  WorkerReply,
  ScanOptions,
  ScanResult,
  DisasmResult,
  DisasmMode,
  YaraScanResult,
  YaraRuleUnit,
} from "./protocol";

interface Pending {
  resolve(value: unknown): void;
  reject(reason: unknown): void;
}

export class ScanClient {
  private worker: Worker;
  private nextId = 1;
  private pending = new Map<number, Pending>();
  private inited: Promise<void> | null = null;

  constructor() {
    this.worker = new Worker(new URL("./scan-worker.ts", import.meta.url), {
      type: "module",
      name: "die-scan-worker",
    });
    this.worker.addEventListener("message", (ev: MessageEvent<WorkerReply>) => {
      const p = this.pending.get(ev.data.id);
      if (!p) return;
      this.pending.delete(ev.data.id);
      if (ev.data.ok) p.resolve(ev.data.result);
      else p.reject(new Error(ev.data.error));
    });
  }

  init(opts: { signaturesUrl: string; manifestUrl: string }): Promise<void> {
    if (!this.inited) {
      this.inited = this.send<void>({ cmd: "init", ...opts });
    }
    return this.inited;
  }

  async scan(bytes: ArrayBuffer, options: ScanOptions = {}): Promise<ScanResult> {
    await this.init({
      signaturesUrl: "/signatures-pack/",
      manifestUrl: "/signatures-pack/manifest.json",
    });
    return this.send<ScanResult>(
      { cmd: "scan", bytes, options },
      [bytes],
    );
  }

  async demangle(name: string): Promise<string | null> {
    await this.init({
      signaturesUrl: "/signatures-pack/",
      manifestUrl: "/signatures-pack/manifest.json",
    });
    return this.send<string | null>({ cmd: "demangle", name });
  }

  async disasm(bytes: ArrayBuffer, address: number, count: number, mode: DisasmMode = "auto"): Promise<DisasmResult> {
    await this.init({
      signaturesUrl: "/signatures-pack/",
      manifestUrl: "/signatures-pack/manifest.json",
    });
    return this.send<DisasmResult>({ cmd: "disasm", bytes, address, count, mode });
  }

  async yaraScan(bytes: ArrayBuffer, units: YaraRuleUnit[]): Promise<YaraScanResult> {
    await this.init({
      signaturesUrl: "/signatures-pack/",
      manifestUrl: "/signatures-pack/manifest.json",
    });
    return this.send<YaraScanResult>({ cmd: "yaraScan", bytes, units });
  }

  async extractArchiveEntry(bytes: ArrayBuffer, entryName: string): Promise<ArrayBuffer> {
    await this.init({
      signaturesUrl: "/signatures-pack/",
      manifestUrl: "/signatures-pack/manifest.json",
    });
    return this.send<ArrayBuffer>({ cmd: "extractArchiveEntry", bytes, entryName });
  }

  dispose(): void {
    this.worker.terminate();
  }

  private send<R = unknown>(
    msg: { cmd: WorkerRequest["cmd"] } & Record<string, unknown>,
    transfer: Transferable[] = [],
  ): Promise<R> {
    const id = this.nextId++;
    return new Promise<R>((resolve, reject) => {
      this.pending.set(id, { resolve: (v) => resolve(v as R), reject });
      this.worker.postMessage({ ...msg, id }, transfer);
    });
  }
}
