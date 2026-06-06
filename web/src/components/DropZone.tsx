import { useRef } from "react";

import { useWorkspace } from "../store/workspace";
import { useDropUpload } from "./useDropUpload";

export function DropZone({ compact = false }: { compact?: boolean }) {
  const ingestFiles = useWorkspace((s) => s.ingestFiles);
  const { isDragging, dropHandlers } = useDropUpload();
  const inputRef = useRef<HTMLInputElement | null>(null);

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
          onChange={(e) => e.target.files && void ingestFiles(e.target.files)}
        />
      </button>
    );
  }

  return (
    <div
      {...dropHandlers}
      onClick={() => inputRef.current?.click()}
      className={
        "max-w-xl w-full p-12 border-2 border-dashed rounded-lg text-center cursor-pointer transition-colors " +
        (isDragging ? "border-amber-400 bg-amber-400/5" : "border-zinc-700 hover:border-zinc-500")
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
        onChange={(e) => e.target.files && void ingestFiles(e.target.files)}
      />
    </div>
  );
}
