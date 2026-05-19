
import { useState } from "react";

import { useWorkspace } from "../store/workspace";

const SAMPLE_SYMBOLS = [
  "_ZN5boost6system6detail21generic_category_holderE",
  "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev",
  "_RNvCs1AB_3std4testE",
  "_ZNSt8ios_base4InitC1Ev",
];

export function DemanglerPanel() {
  const client = useWorkspace((s) => s.client);
  const [input, setInput] = useState("");
  const [output, setOutput] = useState<string | null>(null);
  const [status, setStatus] = useState<"idle" | "running" | "done" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  const run = async (symbol: string) => {
    setStatus("running");
    setError(null);
    try {
      const result = await client.demangle(symbol);
      setOutput(result);
      setStatus("done");
    } catch (e) {
      setError((e as Error).message);
      setStatus("error");
    }
  };

  return (
    <div className="p-4 flex flex-col gap-4 max-w-3xl">
      <div>
        <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
          Mangled symbol
        </label>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          rows={3}
          spellCheck={false}
          placeholder="_ZN5boost6system6detail21generic_category_holderE"
          className="w-full px-3 py-2 bg-zinc-900 border border-zinc-800 rounded font-mono text-sm"
        />
        <div className="flex items-center gap-2 mt-2">
          <button
            type="button"
            disabled={!input.trim() || status === "running"}
            onClick={() => run(input.trim())}
            className="px-3 py-1.5 text-sm rounded bg-amber-600 hover:bg-amber-500 disabled:bg-zinc-800 disabled:text-zinc-500"
          >
            {status === "running" ? "Demangling…" : "Demangle"}
          </button>
          <span className="text-xs text-zinc-500">
            Tries GnuV3 → Rust → D → JavaV3 → GNAT
          </span>
        </div>
      </div>

      {output !== null ? (
        <div>
          <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
            Demangled
          </label>
          <pre className="px-3 py-2 bg-zinc-950 border border-zinc-800 rounded font-mono text-sm whitespace-pre-wrap break-all">
            {output || <span className="text-zinc-500 italic">(no result - input may not be a recognized mangled form)</span>}
          </pre>
        </div>
      ) : null}

      {error ? (
        <div className="px-3 py-2 bg-red-950/30 border border-red-900 rounded text-sm text-red-300">
          {error}
        </div>
      ) : null}

      <div>
        <div className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
          Try a sample
        </div>
        <ul className="space-y-1">
          {SAMPLE_SYMBOLS.map((sym) => (
            <li key={sym}>
              <button
                type="button"
                onClick={() => { setInput(sym); void run(sym); }}
                className="text-left text-xs text-zinc-400 hover:text-zinc-200 font-mono break-all"
              >
                {sym}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
