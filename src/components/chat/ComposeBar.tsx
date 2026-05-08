import { useEffect, useRef, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { EmojiPicker } from "./EmojiPicker";

interface Props {
  onSend: (text: string, detonateSecs: number | null) => void;
  onSendAttachment?: (sourcePath: string) => Promise<unknown>;
}

interface DetonateOption {
  label: string;
  secs: number;
}

const DETONATE_OPTIONS: DetonateOption[] = [
  { label: "30 seconds", secs: 30 },
  { label: "5 minutes", secs: 5 * 60 },
  { label: "1 hour", secs: 60 * 60 },
  { label: "12 hours", secs: 12 * 60 * 60 },
  { label: "24 hours", secs: 24 * 60 * 60 },
];

export function ComposeBar({ onSend, onSendAttachment }: Props) {
  const [text, setText] = useState("");
  const [attaching, setAttaching] = useState(false);
  const [attachError, setAttachError] = useState<string | null>(null);
  const [detonateSecs, setDetonateSecs] = useState<number | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [emojiOpen, setEmojiOpen] = useState(false);
  const ref = useRef<HTMLTextAreaElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);

  const insertEmoji = (e: string) => {
    const ta = ref.current;
    if (!ta) {
      setText((t) => t + e);
      return;
    }
    const start = ta.selectionStart ?? text.length;
    const end = ta.selectionEnd ?? text.length;
    const next = text.slice(0, start) + e + text.slice(end);
    setText(next);
    // Restore caret to right after the inserted emoji on next paint.
    requestAnimationFrame(() => {
      if (ref.current) {
        const pos = start + e.length;
        ref.current.focus();
        ref.current.setSelectionRange(pos, pos);
      }
    });
  };

  const submit = () => {
    if (!text.trim()) return;
    onSend(text, detonateSecs);
    setText("");
    ref.current?.focus();
  };

  const onAttach = async () => {
    if (!onSendAttachment || attaching) return;
    setAttachError(null);
    const picked = await open({ multiple: false, directory: false });
    if (!picked || typeof picked !== "string") return;
    setAttaching(true);
    try {
      await onSendAttachment(picked);
    } catch (e) {
      setAttachError(String(e));
    } finally {
      setAttaching(false);
    }
  };

  const onKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  };

  useEffect(() => {
    if (!menuOpen) return;
    const onClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [menuOpen]);

  const detonateLabel =
    detonateSecs === null
      ? null
      : DETONATE_OPTIONS.find((o) => o.secs === detonateSecs)?.label ?? `${detonateSecs}s`;

  return (
    <div className="px-3 py-3 border-t border-border-subtle bg-bg-base">
      {attachError && (
        <div className="mb-2 text-[11px] text-status-err">{attachError}</div>
      )}
      {detonateSecs !== null && (
        <div className="mb-2 flex items-center justify-between text-[11px]">
          <span className="text-accent-400 font-mono uppercase tracking-wider">
            self-detonating · {detonateLabel}
          </span>
          <button
            onClick={() => setDetonateSecs(null)}
            className="text-text-tertiary hover:text-text-primary"
          >
            cancel
          </button>
        </div>
      )}
      <div className="flex items-end gap-2 bg-bg-inset border border-border-default rounded-lg p-2 focus-within:border-accent-500/40">
        <button
          onClick={onAttach}
          disabled={attaching || !onSendAttachment}
          className="btn-ghost p-1 text-text-tertiary hover:text-text-secondary disabled:opacity-40"
          title={
            attaching
              ? "Encrypting attachment…"
              : "Attach file or GIF (max 10 MB)"
          }
        >
          <PaperclipIcon />
        </button>
        <div className="relative">
          <button
            onClick={() => setEmojiOpen((v) => !v)}
            className={`btn-ghost p-1 hover:text-text-secondary ${
              emojiOpen ? "text-accent-400" : "text-text-tertiary"
            }`}
            title="Insert emoji"
          >
            <SmileyIcon />
          </button>
          {emojiOpen && (
            <EmojiPicker
              onPick={(e) => insertEmoji(e)}
              onClose={() => setEmojiOpen(false)}
            />
          )}
        </div>
        <div className="relative" ref={menuRef}>
          <button
            onClick={() => setMenuOpen((v) => !v)}
            className={`btn-ghost p-1 hover:text-text-secondary ${
              detonateSecs !== null ? "text-accent-400" : "text-text-tertiary"
            }`}
            title="Self-detonating message"
          >
            <ClockIcon />
          </button>
          {menuOpen && (
            <div className="absolute bottom-full left-0 mb-2 z-10 w-44 bg-bg-elevated border border-border-default rounded-lg py-1 shadow-xl">
              <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
                detonate after
              </div>
              {DETONATE_OPTIONS.map((opt) => (
                <button
                  key={opt.secs}
                  onClick={() => {
                    setDetonateSecs(opt.secs);
                    setMenuOpen(false);
                  }}
                  className={`w-full text-left px-3 py-1.5 text-xs hover:bg-bg-hover ${
                    detonateSecs === opt.secs
                      ? "text-accent-400"
                      : "text-text-secondary"
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          )}
        </div>
        <textarea
          ref={ref}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={onKey}
          placeholder={
            detonateSecs === null ? "Message" : "Self-detonating message"
          }
          rows={1}
          className="flex-1 bg-transparent text-text-primary placeholder:text-text-tertiary resize-none text-sm leading-relaxed focus:outline-none max-h-32"
        />
        <button
          onClick={submit}
          disabled={!text.trim()}
          className="btn-primary text-xs disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Send
        </button>
      </div>
    </div>
  );
}

function PaperclipIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m21 12-9.5 9.5a5 5 0 0 1-7.07-7.07L13.5 5a3.5 3.5 0 0 1 4.95 4.95l-8.49 8.49a2 2 0 0 1-2.83-2.83L14 8" />
    </svg>
  );
}

function SmileyIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M8 14s1.5 2 4 2 4-2 4-2" />
      <line x1="9" y1="9" x2="9.01" y2="9" />
      <line x1="15" y1="9" x2="15.01" y2="9" />
    </svg>
  );
}

function ClockIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <path d="M12 6v6l4 2" />
    </svg>
  );
}
