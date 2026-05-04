import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { DisplayMessage } from "../../stores/conversationStore";
import { formatTime, formatBytes } from "../../utils/formatters";

export function MessageBubble({ m }: { m: DisplayMessage }) {
  const align = m.is_outbound ? "items-end" : "items-start";
  const bg = m.is_outbound
    ? "bg-accent-500/10 border border-accent-500/20"
    : "bg-bg-raised border border-border-subtle";

  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (m.disappear_at === null) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [m.disappear_at]);

  // Defense in depth: regardless of the backend sweep timing, hide the
  // bubble locally as soon as the AEAD-embedded TTL elapses. The DB sweep
  // still purges the row from disk on its 10s tick.
  if (m.disappear_at !== null && m.disappear_at <= now) {
    return null;
  }

  return (
    <div className={`flex flex-col ${align}`}>
      <div className={`max-w-[70%] px-3 py-2 rounded-lg ${bg}`}>
        {!m.is_outbound && (
          <div
            className={`text-[10px] tracking-wider text-text-tertiary mb-0.5 ${
              m.sender_nickname ? "" : "font-mono uppercase"
            }`}
          >
            {m.sender_nickname ?? m.sender_alias}
          </div>
        )}
        {m.is_attachment ? (
          <AttachmentRow m={m} />
        ) : (
          <div className="text-[13px] leading-relaxed text-text-primary whitespace-pre-wrap break-words">
            {m.text ?? <span className="text-text-tertiary italic">decryption pending</span>}
          </div>
        )}
        <div className="flex items-center gap-1.5 mt-1 text-[10px] text-text-tertiary">
          <span>{formatTime(m.created_at)}</span>
          {m.is_outbound && (
            <span
              className={
                m.status === "delivered"
                  ? "text-status-ok"
                  : m.status === "failed"
                  ? "text-status-err"
                  : "text-text-tertiary"
              }
            >
              · {prettyStatus(m.status)}
            </span>
          )}
          {m.disappear_at !== null && (
            <DetonateBadge deadline={m.disappear_at} now={now} />
          )}
        </div>
      </div>
    </div>
  );
}

function DetonateBadge({ deadline, now }: { deadline: number; now: number }) {
  const remaining = Math.max(0, deadline - now);
  return (
    <span className="text-accent-400 font-mono">
      · ⏱ {remaining === 0 ? "0s" : formatRemaining(remaining)}
    </span>
  );
}

function formatRemaining(ms: number): string {
  const total = Math.ceil(ms / 1000);
  if (total < 60) return `${total}s`;
  const m = Math.floor(total / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  return `${d}d`;
}

function prettyStatus(s: string): string {
  switch (s) {
    case "queued":
      return "Sending";
    case "sent":
      return "Sent";
    case "delivered":
      return "Delivered";
    case "failed":
      return "Failed";
    default:
      return s;
  }
}

function AttachmentRow({ m }: { m: DisplayMessage }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const isImage = !!m.mime_type?.startsWith("image/");
  const [imgSrc, setImgSrc] = useState<string | null>(null);
  const [imgErr, setImgErr] = useState<string | null>(null);

  useEffect(() => {
    if (!isImage) return;
    let cancelled = false;
    invoke<string>("attachment_load_data_url", {
      messageId: m.id,
      conversationId: m.conversation_id,
      mimeType: m.mime_type,
    })
      .then((url) => {
        if (!cancelled) setImgSrc(url);
      })
      .catch((e) => {
        if (!cancelled) setImgErr(String(e));
      });
    return () => {
      cancelled = true;
    };
  }, [isImage, m.id, m.conversation_id, m.mime_type]);

  const onSave = async () => {
    if (busy) return;
    setErr(null);
    const dest = await save({
      defaultPath: m.filename ?? "attachment",
    });
    if (!dest) return;
    setBusy(true);
    try {
      await invoke("attachment_save_as", {
        messageId: m.id,
        conversationId: m.conversation_id,
        destPath: dest,
      });
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-1.5">
      {isImage && (
        <div className="rounded-md overflow-hidden border border-border-subtle bg-bg-inset">
          {imgSrc ? (
            <img
              src={imgSrc}
              alt={m.filename ?? "attachment"}
              className="block max-w-[280px] max-h-[280px] object-contain"
            />
          ) : imgErr ? (
            <div className="px-2 py-1 text-[10px] text-status-err">{imgErr}</div>
          ) : (
            <div className="w-[280px] h-[140px] flex items-center justify-center text-[10px] text-text-tertiary">
              Decrypting…
            </div>
          )}
        </div>
      )}
      <div className="flex items-center gap-2">
        <FileIcon />
        <div className="flex flex-col min-w-0">
          <span className="text-[12px] text-text-primary truncate">
            {m.filename ?? "file"}
          </span>
          <span className="text-[10px] text-text-tertiary">
            {m.mime_type ?? "application/octet-stream"}
            {m.file_size ? ` · ${formatBytes(m.file_size)}` : ""}
          </span>
        </div>
        <button
          onClick={onSave}
          disabled={busy}
          className="ml-auto text-[10px] font-mono uppercase tracking-wider text-accent-400 hover:text-accent-300 disabled:opacity-40"
        >
          {busy ? "Saving…" : "Save"}
        </button>
      </div>
      {err && <div className="text-[10px] text-status-err">{err}</div>}
    </div>
  );
}

function FileIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="text-text-tertiary flex-shrink-0"
    >
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
    </svg>
  );
}
