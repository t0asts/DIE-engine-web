import { useCallback, useRef, useState } from "react";

import { useWorkspace } from "../store/workspace";

function makeId(name: string): string {
  return `${name}::${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

export function DropZone({ compact = false }: { compact?: boolean }) {
  const addFile = useWorkspace((s) => s.addFile);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const handleFiles = useCallback(
    async (list: FileList) => {
      for (const file of Array.from(list)) {
        const buf = await file.arrayBuffer();
        await addFile({ id: makeId(file.name), name: file.name, size: file.size, bytes: buf });
      }
    },
    [addFile],
  );

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files) void handleFiles(e.dataTransfer.files);
  };

  if (compact) {
    return (
      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        className="w-full text-xs px-3 py-2 rounded bg-zinc-800 hover:bg-zinc-700"
      >
        Add file…
        <input
          type="file"
          ref={inputRef}
          className="hidden"
          multiple
          onChange={(e) => e.target.files && void handleFiles(e.target.files)}
        />
      </button>
    );
  }

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      onClick={() => inputRef.current?.click()}
      className={
        "max-w-xl w-full p-12 border-2 border-dashed rounded-lg text-center cursor-pointer transition-colors " +
        (dragging ? "border-amber-400 bg-amber-400/5" : "border-zinc-700 hover:border-zinc-500")
      }
    >
      <div className="text-lg font-medium">Drop a file here</div>
      <div className="text-sm text-zinc-400 mt-2">
        PE, ELF, Mach-O, .apk, .pdf, archives
      </div>
      <input
        type="file"
        ref={inputRef}
        className="hidden"
        multiple
        onChange={(e) => e.target.files && void handleFiles(e.target.files)}
      />
    </div>
  );
}
