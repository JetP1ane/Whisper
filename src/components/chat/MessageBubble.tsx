import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { DisplayMessage, ReactionGroup } from "../../stores/conversationStore";
import { formatTime, formatBytes } from "../../utils/formatters";

const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🙏", "🔥", "🎉"];

export function MessageBubble({ m }: { m: DisplayMessage }) {
  const align = m.is_outbound ? "items-end" : "items-start";
  // Solid matte fills following the iMessage / Signal / Telegram
  // dark-mode pattern: both bubbles dark, both light text. The
  // sender's blue tint is the only saturated colour on screen,
  // which keeps the visual hierarchy correct ("my messages stand
  // out, theirs sit in the chrome").
  //   sender   → blue-600 (#2563EB) with white text  — passes WCAG AA
  //   receiver → gray-800 (#1F2937) with white text  — passes WCAG AA
  const bg = m.is_outbound
    ? "bg-blue-600 border border-blue-600 text-white"
    : "bg-gray-800 border border-gray-800 text-white";
  // Faded variant of the bubble's foreground colour, used for the
  // sender alias header, timestamp + status row, and "decryption
  // pending" italic. Both bubbles share the white-with-alpha
  // treatment now — they have the same body text colour.
  const subtleClass = "text-white/70";

  const [now, setNow] = useState(() => Date.now());
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  // Tick once a second when the bubble has either a disappearing
  // timer OR an outbound queued status — the latter is so the label
  // can transition from "Sending…" → "Queued · trying" → "Recipient
  // offline" without the user having to reload anything.
  const isOutboundQueued = m.is_outbound && m.status === "queued";
  useEffect(() => {
    if (m.disappear_at === null && !isOutboundQueued) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [m.disappear_at, isOutboundQueued]);

  // Defense in depth: regardless of the backend sweep timing, hide the
  // bubble locally as soon as the AEAD-embedded TTL elapses. The DB sweep
  // still purges the row from disk on its 10s tick.
  if (m.disappear_at !== null && m.disappear_at <= now) {
    return null;
  }

  const onContextMenu = (e: React.MouseEvent<HTMLDivElement>) => {
    e.preventDefault();
    setMenu({ x: e.clientX, y: e.clientY });
  };

  const react = async (emoji: string, remove: boolean) => {
    setMenu(null);
    try {
      await invoke("message_react", {
        messageId: m.id,
        emoji,
        remove,
      });
    } catch {
      /* swallow — bubble re-renders on next message:reaction event */
    }
  };

  return (
    <div className={`flex flex-col ${align}`}>
      <div
        className={`max-w-[70%] px-3 py-2 rounded-lg ${bg}`}
        onContextMenu={onContextMenu}
      >
        {!m.is_outbound && (
          <div
            className={`text-[10px] tracking-wider ${subtleClass} mb-0.5 ${
              m.sender_nickname ? "" : "font-mono uppercase"
            }`}
          >
            {m.sender_nickname ?? m.sender_alias}
          </div>
        )}
        {m.is_attachment ? (
          <AttachmentRow m={m} />
        ) : (
          <div className="text-[13px] leading-relaxed whitespace-pre-wrap break-words">
            {m.text ?? <span className={`${subtleClass} italic`}>decryption pending</span>}
          </div>
        )}
        <div className={`flex items-center gap-1.5 mt-1 text-[10px] ${subtleClass}`}>
          <span>{formatTime(m.created_at)}</span>
          {m.is_outbound && (
            <OutboundStatusBadge m={m} now={now} />
          )}
          {m.disappear_at !== null && (
            <DetonateBadge deadline={m.disappear_at} now={now} />
          )}
        </div>
      </div>
      {m.reactions.length > 0 && (
        <ReactionRow
          reactions={m.reactions}
          align={m.is_outbound ? "end" : "start"}
          onToggle={(emoji, mine) => react(emoji, mine)}
        />
      )}
      {menu && (
        <ReactionMenu
          x={menu.x}
          y={menu.y}
          existing={m.reactions}
          onPick={(emoji) => {
            const own = m.reactions.find((r) => r.emoji === emoji && r.mine);
            react(emoji, !!own);
          }}
          onClose={() => setMenu(null)}
        />
      )}
    </div>
  );
}

function ReactionRow({
  reactions,
  align,
  onToggle,
}: {
  reactions: ReactionGroup[];
  align: "start" | "end";
  onToggle: (emoji: string, mine: boolean) => void;
}) {
  return (
    <div
      className={`mt-1 flex flex-wrap gap-1 ${
        align === "end" ? "justify-end" : "justify-start"
      }`}
    >
      {reactions.map((r) => (
        <button
          key={r.emoji}
          onClick={() => onToggle(r.emoji, r.mine)}
          className={`text-[11px] px-1.5 py-0.5 rounded-full border transition-colors ${
            r.mine
              ? "bg-accent-500/15 border-accent-500/40 text-text-primary"
              : "bg-bg-inset border-border-subtle text-text-secondary hover:bg-bg-hover"
          }`}
          title={r.mine ? "You reacted — click to remove" : "Click to add"}
        >
          {r.emoji}
          {r.count > 1 && (
            <span className="ml-1 font-mono tabular-nums text-[10px] text-text-tertiary">
              {r.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

function ReactionMenu({
  x,
  y,
  existing,
  onPick,
  onClose,
}: {
  x: number;
  y: number;
  existing: ReactionGroup[];
  onPick: (emoji: string) => void;
  onClose: () => void;
}) {
  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest("[data-reaction-menu]")) onClose();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [onClose]);

  // Clamp inside viewport so we don't render off-screen.
  const left = Math.min(x, window.innerWidth - 280);
  const top = Math.min(y, window.innerHeight - 60);

  return (
    <div
      data-reaction-menu
      className="fixed z-50 bg-bg-panel border border-border-default rounded-lg shadow-xl px-2 py-1.5 flex items-center gap-1 animate-fade-in"
      style={{ left, top }}
    >
      {QUICK_REACTIONS.map((emoji) => {
        const own = existing.find((r) => r.emoji === emoji && r.mine);
        return (
          <button
            key={emoji}
            onClick={() => onPick(emoji)}
            className={`text-lg px-1.5 py-0.5 rounded transition-colors ${
              own
                ? "bg-accent-500/20 hover:bg-accent-500/30"
                : "hover:bg-bg-hover"
            }`}
            title={own ? "Remove your reaction" : "React"}
          >
            {emoji}
          </button>
        );
      })}
    </div>
  );
}

// (TransportBadge removed: I2P is the only transport, so the "· I2P"
// suffix on every delivered message was redundant. The relay branch
// was dead code from the pre-I2P-only era.)

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

/// Bubble status renderer.
///
/// Splits the generic `queued` state into three honest sub-states
/// based on local outbox observables (no presence beacons, no wire
/// signal). The user's biggest pain point — "Sending" sticking for 15
/// minutes — comes from collapsing all of these into one label. Now:
///
///   - first ~10s after send, no attempts yet  →  "Sending…"
///   - 1+ failed attempts, last try was recent →  "Queued · retrying"
///   - 5+ failed attempts OR last try >2 min ago → "Recipient offline"
///   - sent / delivered / failed                →  unchanged
///
/// All thresholds derived from `attempt_count` + `last_attempt_at`
/// surfaced by `conversation_messages`. The bubble re-renders every
/// second while `status === 'queued'` so transitions are visible
/// without a manual refresh.
function OutboundStatusBadge({
  m,
  now,
}: {
  m: DisplayMessage;
  now: number;
}) {
  // Status text is rendered inside the sender bubble (always outbound).
  // The bubble's white text colour cascades through; we deliberately
  // drop the per-state colour overrides (emerald for delivered, red
  // for failed, tertiary-grey for the rest) so every state reads in
  // the same matte white the rest of the bubble uses. Differentiation
  // is by the label text itself + the hover-tooltip.
  if (m.status === "delivered") {
    return <span>· Delivered</span>;
  }
  if (m.status === "failed") {
    return <span title="Send failed. The recipient may be offline; the queue will keep trying.">· Failed</span>;
  }
  if (m.status === "sent") {
    return <span>· Sent</span>;
  }
  // status === "queued"
  const attempts = m.attempt_count ?? 0;
  const lastAt = m.last_attempt_at;
  const ageSecs = lastAt ? Math.floor((now - lastAt) / 1000) : null;

  // Phase A: no attempts yet. Either we're still inside the inline
  // try_i2p_deliver retry ladder (~7s) or the message just hit the
  // queue and the next worker tick is imminent.
  if (attempts === 0) {
    return <span title="Establishing route to recipient.">· Sending…</span>;
  }

  // Phase C: enough failures that we should tell the user the
  // recipient appears offline. Threshold tuned to match the queue
  // worker's backoff (5,15,30,60,300s) — by attempt 5 we're at the
  // 300s plateau, and any attempt older than 120s means the worker
  // is in a long backoff sleep.
  const offline = attempts >= 5 || (ageSecs !== null && ageSecs >= 120);
  if (offline) {
    return (
      <span
        title={`Recipient hasn't been reachable. ${attempts} attempts, last ${
          ageSecs !== null ? `${ageSecs}s ago` : "in progress"
        }. Will keep retrying for up to 30 days.`}
      >
        · Recipient offline · retrying
      </span>
    );
  }

  // Phase B: actively retrying within the short backoff window.
  return (
    <span
      title={`Attempt ${attempts}, last ${
        ageSecs !== null ? `${ageSecs}s ago` : "in progress"
      }. Recipient may be offline.`}
    >
      · Queued · retrying
    </span>
  );
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
