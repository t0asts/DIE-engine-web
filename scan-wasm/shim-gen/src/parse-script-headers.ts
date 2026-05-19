
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { CppMethod, CppParam } from "./types.ts";
import { isHotPath } from "./types.ts";

const VISIBILITY_RE = /^\s*(public|private|protected)(\s+slots)?\s*:\s*$|^\s*(signals)\s*:\s*$/;

const CLASS_RE = /^\s*class\s+(\w+_Script)\s*(?::\s*public\s+(\w+))?\b/;

function parentJsClassOf(baseClass: string | undefined): string | null {
  if (!baseClass || !baseClass.endsWith("_Script")) return null;   
  return baseClass.replace(/_Script$/, "");
}

const METHOD_RE =
  /^\s*(?<ret>(?:virtual\s+)?(?:const\s+)?[\w:<>,\s]+?[\s&*]+)\s*(?<name>\w+)\s*\((?<args>[^()]*)\)\s*(?:const\s*)?;\s*$/;

function stripLineComments(s: string): string {
  return s.replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\
}

function parseParams(argsStr: string): CppParam[] {
  const trimmed = argsStr.trim();
  if (!trimmed) return [];

  const parts: string[] = [];
  let depth = 0;
  let buf = "";
  for (const ch of trimmed) {
    if (ch === "<" || ch === "(") depth++;
    else if (ch === ">" || ch === ")") depth--;
    if (ch === "," && depth === 0) {
      parts.push(buf);
      buf = "";
    } else {
      buf += ch;
    }
  }
  if (buf.trim()) parts.push(buf);

  const params: CppParam[] = [];
  for (const raw of parts) {
    const m = raw.match(/^\s*(?<type>(?:const\s+)?[\w:<>,\s]+?[\s&*]+)\s*(?<name>\w+)\s*(?:=\s*(?<def>.+?))?\s*$/);
    if (!m || !m.groups) {
      throw new Error(`unable to parse parameter: ${JSON.stringify(raw)}`);
    }
    params.push({
      cppType: m.groups.type!.trim(),
      name: m.groups.name!,
      ...(m.groups.def !== undefined ? { defaultValue: m.groups.def!.trim() } : {}),
    });
  }
  return params;
}

export interface ParsedHeader {
  methods: CppMethod[];
  
  parents: Record<string, string | null>;
}

export function parseHeader(path: string): ParsedHeader {
  const src = stripLineComments(readFileSync(path, "utf8"));
  const lines = src.split("\n");

  let className: string | null = null;
  let parentJsClass: string | null = null;
  let inPublicSlots = false;
  const methods: CppMethod[] = [];
  const parents: Record<string, string | null> = {};

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();

    const cm = line.match(CLASS_RE);
    if (cm) {
      className = cm[1] ?? null;
      parentJsClass = parentJsClassOf(cm[2]);
      if (className) parents[className.replace(/_Script$/, "")] = parentJsClass;
      inPublicSlots = false;
      continue;
    }

    if (className) {
      const vm = line.match(VISIBILITY_RE);
      if (vm) {
        inPublicSlots = vm[1] === "public" && vm[2] !== undefined;
        continue;
      }
    }

    if (!className || !inPublicSlots) continue;
    if (!line.includes("(") || !line.endsWith(";")) continue;

    const mm = line.match(METHOD_RE);
    if (!mm || !mm.groups) continue;

    if (mm.groups.name === className || mm.groups.name === "~" + className) continue;

    const params = parseParams(mm.groups.args!);
    const cppReturn = mm.groups.ret!.replace(/\bvirtual\b/g, "").trim();
    const name = mm.groups.name!;

    methods.push({
      className,
      jsClass: className.replace(/_Script$/, ""),
      parentJsClass,
      name,
      cppReturn,
      params,
      isHotPath: isHotPath({ name, cppReturn, params }),
      methodId: -1, 
    });
  }

  return { methods, parents };
}

export function parseAllHeaders(modulesDir: string): ParsedHeader {
  const files = readdirSync(modulesDir)
    .filter((f) => f.endsWith("_script.h"))
    .sort()
    .map((f) => join(modulesDir, f));

  const methods: CppMethod[] = [];
  const parents: Record<string, string | null> = {};
  for (const f of files) {
    const parsed = parseHeader(f);
    methods.push(...parsed.methods);
    Object.assign(parents, parsed.parents);
  }
  return { methods, parents };
}

export function assignMethodIds(methods: CppMethod[]): CppMethod[] {
  const sorted = [...methods].sort((a, b) => {
    if (a.jsClass !== b.jsClass) return a.jsClass < b.jsClass ? -1 : 1;
    if (a.name !== b.name) return a.name < b.name ? -1 : 1;
    return a.params.length - b.params.length;
  });
  return sorted.map((m, i) => ({ ...m, methodId: i }));
}
