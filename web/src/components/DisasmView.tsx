import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { useWorkspace } from "../store/workspace";
import type { DisasmInsn, DisasmMode } from "../worker/protocol";

interface Props {
  bytes: ArrayBuffer;
  entryPoint: number;
  arch: string;
  onDecompile?: (addr: number) => void;
}

const PAGE = 2000;

const ARM32_ARCH_RE = /^(?:arm(?:nt|_v[67]s?|_a500)?|thumb)$/i;

const MODE_OPTIONS: { id: DisasmMode; label: string }[] = [
  { id: "auto",    label: "Auto" },
  { id: "arm",     label: "ARM" },
  { id: "thumb",   label: "Thumb" },
  { id: "cortexm", label: "Cortex-M" },
];

const hex = (n: number) => "0x" + Math.max(0, Math.trunc(n)).toString(16);
function padHexBytes(s: string, width = 8): string {
  const pairs = s.match(/../g) ?? [];
  return pairs.join(" ").padEnd(width * 3 - 1, " ");
}

export function DisasmView({ bytes, entryPoint, arch, onDecompile }: Props) {
  const client = useWorkspace((s) => s.client);
  const isArm32 = ARM32_ARCH_RE.test(arch);
  const hasEP = Number.isFinite(entryPoint) && entryPoint > 0;
  const [base, setBase] = useState<number>(hasEP ? entryPoint : 0);
  const [mode, setMode] = useState<DisasmMode>("auto");
  const [resolvedMode, setResolvedMode] = useState<string>("");
  const [insns, setInsns] = useState<DisasmInsn[]>([]);
  const [status, setStatus] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [atEnd, setAtEnd] = useState(false);
  const [gotoStr, setGotoStr] = useState("");
  const listRef = useRef<HTMLDivElement>(null);

  const addrIndex = useMemo(() => {
    const m = new Map<number, number>();
    insns.forEach((ins, i) => m.set(ins.address, i));
    return m;
  }, [insns]);

  const load = useCallback(
    async (startAddr: number, append: boolean) => {
      setStatus("loading");
      setError(null);
      try {
        const got = await client.disasm(bytes, startAddr, PAGE, mode);
        setResolvedMode(got.mode);
        if (append) {
          setInsns((prev) => {
            const seen = new Set(prev.map((i) => i.address));
            const fresh = got.insns.filter((i) => !seen.has(i.address));
            if (fresh.length === 0) setAtEnd(true);
            return prev.concat(fresh);
          });
        } else {
          setInsns(got.insns);
          setAtEnd(false);
          if (listRef.current) listRef.current.scrollTop = 0;
        }
        setStatus("done");
      } catch (e) {
        setError((e as Error).message);
        setStatus("error");
      }
    },
    [client, bytes, mode],
  );

  useEffect(() => {
    void load(base, false);
  }, [base, load]);

  const jumpTo = (addr: number) => {
    if (!Number.isFinite(addr)) return;
    if (addrIndex.has(addr)) {
      document.getElementById(`insn-${addr}`)?.scrollIntoView({ block: "center" });
    } else {
      setBase(addr);
    }
  };

  const onGoto = () => {
    const s = gotoStr.trim().replace(/^0x/i, "");
    if (!s) return;
    const v = parseInt(s, 16);
    if (Number.isFinite(v)) jumpTo(v);
  };

  const continueDown = () => {
    const last = insns[insns.length - 1];
    if (!last) return;
    void load(last.address + last.size, true);
  };

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <div className="flex flex-wrap items-center gap-2 mb-3">
        {hasEP ? (
          <button
            type="button"
            onClick={() => (base === entryPoint ? void load(entryPoint, false) : setBase(entryPoint))}
            className="px-2 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700"
          >
            → Entry point ({hex(entryPoint)})
          </button>
        ) : null}
        <input
          type="text"
          placeholder="Go to address (0x…)"
          value={gotoStr}
          onChange={(e) => setGotoStr(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") onGoto(); }}
          className="px-2 py-1 text-xs bg-zinc-900 border border-zinc-800 rounded font-mono w-44"
        />
        <button type="button" onClick={onGoto} className="px-2 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700">
          Go
        </button>
        {isArm32 ? (
          <span className="inline-flex items-center gap-1 ml-1">
            {MODE_OPTIONS.map((o) => (
              <button
                key={o.id}
                type="button"
                onClick={() => setMode(o.id)}
                className={
                  "px-2 py-1 text-xs rounded " +
                  (mode === o.id ? "bg-sky-600 text-white" : "bg-zinc-800 hover:bg-zinc-700")
                }
                title={o.id === "auto" ? "Guess ARM vs Thumb from the binary" : `Force ${o.label}`}
              >
                {o.label}
              </button>
            ))}
            {resolvedMode ? <span className="text-xs text-zinc-500 ml-1">→ {resolvedMode}</span> : null}
          </span>
        ) : null}
        {onDecompile ? (
          <button
            type="button"
            onClick={() => onDecompile(insns[0]?.address ?? base)}
            className="px-2 py-1 text-xs rounded bg-zinc-800 hover:bg-zinc-700"
            title="Decompile the function at the current address"
          >
            Decompile
          </button>
        ) : null}
        <span className="text-xs text-zinc-500">
          {status === "loading" ? "decoding…" : `${insns.length} insns from ${hex(insns[0]?.address ?? base)}`}
        </span>
      </div>

      {status === "error" ? (
        <div className="text-red-400 text-xs font-mono mb-2">disasm failed: {error}</div>
      ) : null}

      <div ref={listRef} className="flex-1 overflow-auto border border-zinc-800 rounded font-mono text-xs">
        {insns.length === 0 && status === "done" ? (
          <div className="px-3 py-6 text-center text-zinc-500">
            Nothing to disassemble at {hex(base)} (not a mapped/executable address?).
          </div>
        ) : (
          <table className="w-full">
            <tbody>
              {insns.map((ins, i) => (
                <tr key={i} id={`insn-${ins.address}`} className="hover:bg-zinc-900/50">
                  <td className="px-3 py-0.5 text-zinc-500 whitespace-nowrap w-32 align-top">{hex(ins.address)}</td>
                  <td className="px-3 py-0.5 text-zinc-600 whitespace-pre w-52 align-top">{padHexBytes(ins.hex)}</td>
                  <td className="px-2 py-0.5 text-sky-300 whitespace-nowrap w-24 align-top">{ins.mnemonic}</td>
                  <td className="px-2 py-0.5 text-zinc-300 align-top">
                    {ins.operands}
                    {ins.branch !== undefined ? (
                      <button
                        type="button"
                        onClick={() => jumpTo(ins.branch!)}
                        className="ml-2 text-amber-400 hover:underline"
                        title={`Follow → ${hex(ins.branch)}`}
                      >
                        → {hex(ins.branch)}
                      </button>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {insns.length > 0 ? (
          atEnd ? (
            <div className="px-3 py-1.5 text-xs text-zinc-600 border-t border-zinc-900 text-center">
              - end of mapped image -
            </div>
          ) : (
            <button
              type="button"
              onClick={continueDown}
              disabled={status === "loading"}
              className="block w-full px-3 py-1.5 text-xs text-zinc-400 hover:bg-zinc-900 border-t border-zinc-900 disabled:opacity-50"
            >
              {status === "loading" ? "…" : "▼ continue decoding"}
            </button>
          )
        ) : null}
      </div>
    </div>
  );
}
