import { writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { BindingManifest, CppMethod } from "./types.ts";
import { jsTypeOf } from "./types.ts";

interface EmitOptions {
  manifestPath: string;
  shimsPath: string;
  generatedFrom: { repo: string; commit?: string; headers: string[] };
}

function jsParamSig(
  m: CppMethod,
): { name: string; type: string; optional: boolean }[] {
  return m.params.map((p) => ({
    name: p.name,
    type: jsTypeOf(p.cppType),
    optional: p.defaultValue !== undefined,
  }));
}

function hotPathExportName(m: CppMethod): string {
  return `die_${m.jsClass.toLowerCase()}_${m.name}`;
}

export function buildManifest(
  methods: CppMethod[],
  parents: Record<string, string | null>,
  generatedFrom: EmitOptions["generatedFrom"],
): BindingManifest {
  const byClass = new Map<string, CppMethod[]>();
  for (const m of methods) {
    if (!byClass.has(m.jsClass)) byClass.set(m.jsClass, []);
    byClass.get(m.jsClass)!.push(m);
  }

  const hotPathExports: string[] = [];
  const classes: BindingManifest["classes"] = [];

  for (const [jsClass, ms] of [...byClass.entries()].sort()) {
    const cppClass = ms[0]!.className;
    classes.push({
      name: jsClass,
      cppClass,
      methods: ms.map((m) => {
        const out = {
          name: m.name,
          methodId: m.methodId,
          jsReturn: jsTypeOf(m.cppReturn),
          jsParams: jsParamSig(m),
          isHotPath: m.isHotPath,
          ...(m.isHotPath ? { hotPathExport: hotPathExportName(m) } : {}),
        };
        if (m.isHotPath) hotPathExports.push(hotPathExportName(m));
        return out;
      }),
    });
  }

  return {
    version: 1,
    generatedFrom,
    hotPathExports: [...new Set(hotPathExports)].sort(),
    parents,
    classes,
  };
}

function emitTs(manifest: BindingManifest): string {
  const lines: string[] = [];

  lines.push("import type { SessionHandle } from \"./session\";");
  lines.push("");
  lines.push(`export const BINDING_VERSION = ${manifest.version};`);
  lines.push("");
  lines.push("export const METHOD_IDS = {");
  for (const cls of manifest.classes) {
    lines.push(`  ${cls.name}: {`);
    for (const m of cls.methods) {
      lines.push(`    ${quoteKey(m.name)}: ${m.methodId},`);
    }
    lines.push(`  },`);
  }
  lines.push("} as const;");
  lines.push("");
  lines.push("export const HOT_PATH_EXPORTS = [");
  for (const name of manifest.hotPathExports) {
    lines.push(`  ${JSON.stringify(name)},`);
  }
  lines.push("] as const;");
  lines.push("");
  lines.push("export const CLASS_PARENTS: Record<string, string | null> = {");
  for (const [k, v] of Object.entries(manifest.parents).sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    lines.push(`  ${quoteKey(k)}: ${v === null ? "null" : JSON.stringify(v)},`);
  }
  lines.push("};");
  lines.push("");
  lines.push("export function bindingChain(jsClass: string): string[] {");
  lines.push("  const chain: string[] = [];");
  lines.push("  const seen = new Set<string>();");
  lines.push("  let cur: string | null = jsClass;");
  lines.push("  while (cur && !seen.has(cur)) {");
  lines.push("    seen.add(cur);");
  lines.push("    chain.unshift(cur);");
  lines.push("    cur = CLASS_PARENTS[cur] ?? null;");
  lines.push("  }");
  lines.push("  return chain;");
  lines.push("}");
  lines.push("");

  for (const cls of manifest.classes) {
    lines.push(`export interface ${cls.name}Api {`);
    for (const m of cls.methods) {
      const params = m.jsParams
        .map((p) => `${safeIdent(p.name)}${p.optional ? "?" : ""}: ${p.type}`)
        .join(", ");
      lines.push(`  ${quoteKey(m.name)}(${params}): ${m.jsReturn};`);
    }
    lines.push("}");
    lines.push("");
  }

  lines.push("export interface BindingsApi {");
  for (const cls of manifest.classes) {
    lines.push(`  ${cls.name}: ${cls.name}Api;`);
  }
  lines.push("}");
  lines.push("");
  lines.push("export function makeBindings(session: SessionHandle): BindingsApi {");
  lines.push("  const api = {} as BindingsApi;");
  for (const cls of manifest.classes) {
    lines.push(`  api.${cls.name} = {`);
    for (const m of cls.methods) {
      const argNames = m.jsParams.map((p) => safeIdent(p.name)).join(", ");
      const callArgs = m.jsParams.length ? `[${argNames}]` : "[]";
      const params = m.jsParams
        .map((p) => `${safeIdent(p.name)}${p.optional ? "?" : ""}: ${p.type}`)
        .join(", ");
      if (m.isHotPath) {
        const exp = m.hotPathExport!;
        lines.push(
          `    ${quoteKey(m.name)}: ((${params}) => session.hot(${JSON.stringify(exp)}, ${callArgs})) as ${cls.name}Api[${JSON.stringify(m.name)}],`,
        );
      } else {
        lines.push(
          `    ${quoteKey(m.name)}: ((${params}) => session.invoke(${m.methodId}, ${callArgs})) as ${cls.name}Api[${JSON.stringify(m.name)}],`,
        );
      }
    }
    lines.push(`  };`);
  }
  lines.push("  return api;");
  lines.push("}");

  return lines.join("\n") + "\n";
}

function quoteKey(name: string): string {
  return /^[A-Za-z_$][\w$]*$/.test(name) ? name : JSON.stringify(name);
}

const TS_RESERVED = new Set([
  "default", "function", "delete", "new", "class", "import", "export",
  "in", "of", "this", "typeof", "void", "yield", "let", "const", "var",
  "if", "else", "for", "while", "return", "switch", "case",
]);
function safeIdent(name: string): string {
  return TS_RESERVED.has(name) ? `_${name}` : name;
}

export function emit(
  methods: CppMethod[],
  parents: Record<string, string | null>,
  opts: EmitOptions,
): void {
  const manifest = buildManifest(methods, parents, opts.generatedFrom);

  mkdirSync(dirname(opts.manifestPath), { recursive: true });
  writeFileSync(opts.manifestPath, JSON.stringify(manifest, null, 2) + "\n");

  mkdirSync(dirname(opts.shimsPath), { recursive: true });
  writeFileSync(opts.shimsPath, emitTs(manifest));
}
