
import { execSync } from "node:child_process";
import { existsSync, readdirSync } from "node:fs";
import { resolve, join } from "node:path";

import { parseAllHeaders, assignMethodIds } from "./parse-script-headers.ts";
import { emit } from "./emit-shims.ts";
import { emitCppDispatch } from "./emit-cpp-dispatch.ts";

const HERE = resolve(new URL(".", import.meta.url).pathname);
const REPO_ROOT = resolve(HERE, "../../..");
const DIE_ROOT = resolve(REPO_ROOT, "scan-wasm/third_party/DIE-engine");
const MODULES_DIR = resolve(DIE_ROOT, "XScanEngine/modules");
const MANIFEST_OUT = resolve(REPO_ROOT, "scan-wasm/dist/bindings-manifest.json");
const SHIMS_OUT = resolve(REPO_ROOT, "web/src/wasm-bindings/_generated.ts");
const CPP_DISPATCH_OUT = resolve(REPO_ROOT, "scan-wasm/src/bridge_dispatch.cpp");

function getCommit(dir: string): string | undefined {
  try {
    return execSync("git rev-parse --short HEAD", { cwd: dir, stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim();
  } catch {
    return undefined;
  }
}

function main(): void {
  if (!existsSync(MODULES_DIR)) {
    console.error(`error: ${MODULES_DIR} not found`);
    console.error("hint: run from scan-wasm/shim-gen/ after initializing DIE-engine submodules");
    process.exit(1);
  }

  const headerFiles = readdirSync(MODULES_DIR).filter((f) => f.endsWith("_script.h")).sort();
  const generatedFrom = {
    repo: "DIE-engine/XScanEngine/modules",
    ...(getCommit(DIE_ROOT) ? { commit: getCommit(DIE_ROOT)! } : {}),
    headers: headerFiles.map((f) => join("XScanEngine/modules", f)),
  };

  const parsed = parseAllHeaders(MODULES_DIR);
  const methods = assignMethodIds(parsed.methods);

  emit(methods, parsed.parents, {
    manifestPath: MANIFEST_OUT,
    shimsPath: SHIMS_OUT,
    generatedFrom,
  });
  emitCppDispatch(methods, { outPath: CPP_DISPATCH_OUT });

  const byClass = new Map<string, number>();
  let hotCount = 0;
  for (const m of methods) {
    byClass.set(m.jsClass, (byClass.get(m.jsClass) ?? 0) + 1);
    if (m.isHotPath) hotCount++;
  }
  console.log(`parsed ${methods.length} methods across ${byClass.size} binding classes (${hotCount} hot-path)`);
  for (const [cls, n] of [...byClass.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${cls.padEnd(12)} ${n}`);
  }
  console.log(`wrote: ${MANIFEST_OUT}`);
  console.log(`wrote: ${SHIMS_OUT}`);
  console.log(`wrote: ${CPP_DISPATCH_OUT}`);
}

main();
