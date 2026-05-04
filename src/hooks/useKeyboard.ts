import { useEffect } from "react";

interface Handlers {
  onCmdK?: () => void;
  onCmdN?: () => void;
  onCmdShiftN?: () => void;
  onCmdComma?: () => void;
  onCmdL?: () => void;
  onEscape?: () => void;
}

export function useKeyboard(h: Handlers) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const cmd = e.metaKey || e.ctrlKey;
      if (cmd && e.key.toLowerCase() === "k") {
        e.preventDefault();
        h.onCmdK?.();
      } else if (cmd && e.shiftKey && e.key.toLowerCase() === "n") {
        e.preventDefault();
        h.onCmdShiftN?.();
      } else if (cmd && e.key.toLowerCase() === "n") {
        e.preventDefault();
        h.onCmdN?.();
      } else if (cmd && e.key === ",") {
        e.preventDefault();
        h.onCmdComma?.();
      } else if (cmd && e.key.toLowerCase() === "l") {
        e.preventDefault();
        h.onCmdL?.();
      } else if (e.key === "Escape") {
        h.onEscape?.();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [h]);
}
