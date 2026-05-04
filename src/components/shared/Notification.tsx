import { useEffect } from "react";

export type ToastTone = "info" | "success" | "warn" | "error";

interface Props {
  tone?: ToastTone;
  message: string;
  onDismiss: () => void;
  ttlMs?: number;
}

export function Notification({ tone = "info", message, onDismiss, ttlMs = 4000 }: Props) {
  useEffect(() => {
    const t = setTimeout(onDismiss, ttlMs);
    return () => clearTimeout(t);
  }, [onDismiss, ttlMs]);

  const toneCls =
    tone === "success"
      ? "border-status-ok/30 text-status-ok"
      : tone === "warn"
      ? "border-status-warn/30 text-status-warn"
      : tone === "error"
      ? "border-status-err/30 text-status-err"
      : "border-border-default text-text-secondary";

  return (
    <div
      className={`fixed bottom-4 right-4 z-50 max-w-xs panel border rounded-md px-3 py-2 text-xs animate-slide-up ${toneCls}`}
    >
      {message}
    </div>
  );
}
