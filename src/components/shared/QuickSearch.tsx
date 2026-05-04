import { useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  conversationLabel,
  useConversationStore,
} from "../../stores/conversationStore";

interface Props {
  onClose: () => void;
}

interface MessageHit {
  message_id: string;
  conversation_id: string;
  conversation_label: string;
  sender_alias: string;
  snippet: string;
  created_at: number;
}

export function QuickSearch({ onClose }: Props) {
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<MessageHit[]>([]);
  const [searching, setSearching] = useState(false);
  const ref = useRef<HTMLInputElement>(null);
  const conversations = useConversationStore((s) => s.conversations);
  const select = useConversationStore((s) => s.selectConversation);

  useEffect(() => {
    ref.current?.focus();
  }, []);

  // Conversation filter — case-insensitive over the visible label.
  const matchedConvs = useMemo(() => {
    const term = q.trim().toLowerCase();
    if (!term) return conversations.slice(0, 12);
    return conversations.filter((c) =>
      conversationLabel(c).toLowerCase().includes(term),
    );
  }, [conversations, q]);

  // Debounced full-text message search. Skip queries shorter than 2 chars
  // (decryption is per-row, so we don't want to scan everything on a single
  // keystroke).
  useEffect(() => {
    const term = q.trim();
    if (term.length < 2) {
      setHits([]);
      setSearching(false);
      return;
    }
    setSearching(true);
    const t = setTimeout(() => {
      invoke<MessageHit[]>("messages_search", { query: term })
        .then((rows) => setHits(rows))
        .catch(() => setHits([]))
        .finally(() => setSearching(false));
    }, 200);
    return () => clearTimeout(t);
  }, [q]);

  const empty = matchedConvs.length === 0 && hits.length === 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] bg-black/60 animate-fade-in"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[560px] max-w-[90vw] panel border rounded-xl overflow-hidden"
      >
        <input
          ref={ref}
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search conversations and messages"
          className="w-full px-4 py-3 bg-transparent text-text-primary placeholder:text-text-tertiary text-sm focus:outline-none border-b border-border-subtle"
        />
        <div className="max-h-[440px] overflow-y-auto">
          {empty && (
            <div className="px-4 py-6 text-center text-xs text-text-tertiary">
              {q.trim().length === 0
                ? "Start typing to search"
                : searching
                ? "Searching…"
                : "No results"}
            </div>
          )}

          {matchedConvs.length > 0 && (
            <SectionHeader label="Conversations" />
          )}
          {matchedConvs.map((c) => (
            <button
              key={c.id}
              className="w-full text-left px-4 py-2 hover:bg-bg-hover flex items-center gap-3"
              onClick={() => {
                select(c.id);
                onClose();
              }}
            >
              <span className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary w-12 flex-shrink-0">
                {c.kind === "room" ? "room" : "dm"}
              </span>
              <span className="text-sm text-text-primary truncate">
                {conversationLabel(c)}
              </span>
            </button>
          ))}

          {hits.length > 0 && <SectionHeader label="Messages" />}
          {hits.map((h) => (
            <button
              key={h.message_id}
              className="w-full text-left px-4 py-2 hover:bg-bg-hover flex flex-col gap-0.5"
              onClick={() => {
                select(h.conversation_id);
                onClose();
              }}
            >
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
                  {h.conversation_label}
                </span>
                <span className="text-[10px] text-text-tertiary">
                  · {h.sender_alias}
                </span>
                <span className="text-[10px] text-text-tertiary ml-auto">
                  {formatRelative(h.created_at)}
                </span>
              </div>
              <Snippet text={h.snippet} term={q.trim()} />
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function SectionHeader({ label }: { label: string }) {
  return (
    <div className="px-4 pt-2 pb-1 text-[10px] font-mono uppercase tracking-wider text-text-tertiary border-b border-border-subtle bg-bg-inset">
      {label}
    </div>
  );
}

function Snippet({ text, term }: { text: string; term: string }) {
  if (!term) return <span className="text-[12px] text-text-secondary truncate">{text}</span>;
  const lower = text.toLowerCase();
  const idx = lower.indexOf(term.toLowerCase());
  if (idx < 0) return <span className="text-[12px] text-text-secondary truncate">{text}</span>;
  const before = text.slice(0, idx);
  const match = text.slice(idx, idx + term.length);
  const after = text.slice(idx + term.length);
  return (
    <span className="text-[12px] text-text-secondary truncate">
      {before}
      <span className="bg-accent-500/20 text-text-primary rounded px-0.5">
        {match}
      </span>
      {after}
    </span>
  );
}

function formatRelative(unixMs: number): string {
  const diff = Date.now() - unixMs;
  if (diff < 60_000) return "just now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h`;
  return `${Math.floor(diff / 86_400_000)}d`;
}
