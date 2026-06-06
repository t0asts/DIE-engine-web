import { useCallback, useRef, useState } from "react";
import type { DragEvent } from "react";

import { useWorkspace } from "../store/workspace";

function hasFiles(e: DragEvent): boolean {
  return e.dataTransfer.types.includes("Files");
}

export interface DropUpload {
  isDragging: boolean;
  dropHandlers: {
    onDragEnter: (e: DragEvent) => void;
    onDragOver: (e: DragEvent) => void;
    onDragLeave: (e: DragEvent) => void;
    onDrop: (e: DragEvent) => void;
  };
}

export function useDropUpload(): DropUpload {
  const ingestFiles = useWorkspace((s) => s.ingestFiles);
  const depth = useRef(0);
  const [isDragging, setDragging] = useState(false);

  const onDragEnter = useCallback((e: DragEvent) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    depth.current += 1;
    setDragging(true);
  }, []);

  const onDragOver = useCallback((e: DragEvent) => {
    if (hasFiles(e)) e.preventDefault();
  }, []);

  const onDragLeave = useCallback((e: DragEvent) => {
    if (!hasFiles(e)) return;
    depth.current = Math.max(0, depth.current - 1);
    if (depth.current === 0) setDragging(false);
  }, []);

  const onDrop = useCallback(
    (e: DragEvent) => {
      e.preventDefault();
      depth.current = 0;
      setDragging(false);
      if (e.dataTransfer.files.length) void ingestFiles(e.dataTransfer.files);
    },
    [ingestFiles],
  );

  return { isDragging, dropHandlers: { onDragEnter, onDragOver, onDragLeave, onDrop } };
}
