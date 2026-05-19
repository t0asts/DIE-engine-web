
import { useMemo, useState } from "react";

import type { StructNode } from "../worker/protocol";

interface Props {
  structure: StructNode[];
}

function nodeMatches(node: StructNode, f: string): boolean {
  if (!f) return true;
  if (node.name.toLowerCase().includes(f)) return true;
  if (node.value && node.value.toLowerCase().includes(f)) return true;
  return (node.children ?? []).some((c) => nodeMatches(c, f));
}

function TreeNode({
  node,
  filter,
  depth,
  defaultOpen,
}: {
  node: StructNode;
  filter: string;
  depth: number;
  defaultOpen: boolean;
}) {
  const hasKids = !!node.children && node.children.length > 0;
  
  const forcedOpen = filter ? true : undefined;
  const [open, setOpen] = useState(defaultOpen);
  const isOpen = forcedOpen ?? open;

  const visibleKids = useMemo(
    () => (node.children ?? []).filter((c) => nodeMatches(c, filter)),
    [node.children, filter],
  );

  return (
    <div>
      <div
        className={
          "flex items-baseline gap-2 px-2 py-0.5 hover:bg-zinc-900/50 " +
          (hasKids ? "cursor-pointer select-none" : "")
        }
        style={{ paddingLeft: `${8 + depth * 14}px` }}
        onClick={hasKids ? () => setOpen((v) => !v) : undefined}
      >
        {hasKids ? (
          <span className="text-zinc-600 w-3 shrink-0 text-xs">{isOpen ? "▾" : "▸"}</span>
        ) : (
          <span className="w-3 shrink-0" />
        )}
        <span className={hasKids ? "text-zinc-200 font-medium" : "text-zinc-400"}>{node.name}</span>
        {node.value ? (
          <span className="text-zinc-300 font-mono break-all">{node.value}</span>
        ) : null}
      </div>
      {hasKids && isOpen
        ? visibleKids.map((c, i) => (
            
            <TreeNode key={i} node={c} filter={filter} depth={depth + 1} defaultOpen={depth + 1 < 2} />
          ))
        : null}
    </div>
  );
}

export function StructPanel({ structure }: Props) {
  const [filter, setFilter] = useState("");
  const f = filter.trim().toLowerCase();

  const groups = useMemo(() => structure.filter((g) => nodeMatches(g, f)), [structure, f]);

  if (structure.length === 0) {
    return (
      <div className="p-8 text-sm text-zinc-500">
        No structural model available for this format.
      </div>
    );
  }

  return (
    <div className="p-4 flex flex-col h-full min-h-0">
      <input
        type="text"
        placeholder="Filter fields…"
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        className="px-2 py-1 text-sm bg-zinc-900 border border-zinc-800 rounded mb-3 w-full max-w-md"
      />
      <div className="flex-1 overflow-auto border border-zinc-800 rounded text-xs font-mono leading-relaxed">
        {groups.length === 0 ? (
          <div className="px-3 py-6 text-center text-zinc-500">No fields match the filter.</div>
        ) : (
          groups.map((g, i) => (
            
            <TreeNode key={i} node={g} filter={f} depth={0} defaultOpen />
          ))
        )}
      </div>
    </div>
  );
}
