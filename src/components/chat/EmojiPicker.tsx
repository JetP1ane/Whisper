import { useEffect, useRef, useState } from "react";

/**
 * Tiny built-in emoji picker. Pure-local — no network, no third-party
 * library, no licensable emoji data fetch. The set is curated to the
 * common reaction palette that handles ~95% of messenger use.
 *
 * Inserts the emoji's Unicode codepoints into the caller via
 * `onPick(char)`. Rendering uses whatever the host OS's emoji font
 * provides (Apple Color Emoji on macOS), so the emojis match what the
 * user sees system-wide.
 */
const CATEGORIES: { label: string; emojis: string[] }[] = [
  {
    label: "Smileys",
    emojis: [
      "😀", "😃", "😄", "😁", "😆", "🥹", "😅", "😂", "🤣", "🥲",
      "😊", "😇", "🙂", "🙃", "😉", "😌", "😍", "🥰", "😘", "😗",
      "😙", "😚", "😋", "😛", "😝", "😜", "🤪", "🤨", "🧐", "🤓",
      "😎", "🥳", "🥸", "🤩", "🤗", "🤭", "🤫", "🤔", "🤐", "🤨",
    ],
  },
  {
    label: "Reactions",
    emojis: [
      "👍", "👎", "👌", "🤌", "🤏", "✌️", "🤞", "🫰", "🤟", "🤘",
      "🤙", "👈", "👉", "👆", "👇", "☝️", "✋", "🤚", "🖐️", "🖖",
      "👋", "🤝", "🙌", "👏", "🙏", "💪", "🫡", "👀", "🧠", "🦾",
      "❤️", "🧡", "💛", "💚", "💙", "💜", "🖤", "🤍", "🤎", "💔",
      "💯", "💥", "✨", "🔥", "🎉", "🎊", "🥂", "🍾", "🚀", "🌟",
    ],
  },
  {
    label: "Sad/Angry",
    emojis: [
      "😐", "😑", "😶", "🫥", "🫤", "😏", "😒", "🙄", "😬", "😮‍💨",
      "🤥", "😪", "😴", "😷", "🤒", "🤕", "🤢", "🤮", "🥵", "🥶",
      "😵", "😵‍💫", "🤯", "🥴", "😠", "😡", "🤬", "😤", "😭", "😢",
      "😥", "😓", "😨", "😰", "😱", "🥺", "😖", "😣", "😞", "😔",
    ],
  },
  {
    label: "Objects",
    emojis: [
      "📱", "💻", "⌨️", "🖥️", "🖱️", "🖨️", "💾", "💿", "📷", "📹",
      "🎥", "📺", "📻", "🎙️", "🎚️", "🎛️", "⏰", "⏱️", "⏲️", "🕰️",
      "📡", "🔋", "🔌", "💡", "🔦", "🕯️", "🪔", "🧯", "🛢️", "💸",
      "💵", "💴", "💶", "💷", "💳", "🧾", "💎", "🔑", "🗝️", "🔒",
    ],
  },
  {
    label: "Symbols",
    emojis: [
      "✅", "❌", "⚠️", "🚫", "⛔", "❓", "❗", "‼️", "⁉️", "💤",
      "♻️", "✳️", "✴️", "❇️", "©️", "®️", "™️", "🆗", "🆕", "🆒",
      "🆓", "🆙", "🔝", "🔚", "🔙", "🔜", "↩️", "↪️", "🔁", "🔂",
      "🔀", "▶️", "⏸️", "⏯️", "⏹️", "⏺️", "⏭️", "⏮️", "⏩", "⏪",
    ],
  },
];

interface Props {
  onPick: (emoji: string) => void;
  onClose: () => void;
}

export function EmojiPicker({ onPick, onClose }: Props) {
  const [activeCat, setActiveCat] = useState(0);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        onClose();
      }
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

  return (
    <div
      ref={ref}
      className="absolute bottom-full left-0 mb-2 z-20 w-[320px] bg-bg-panel border border-border-default rounded-lg shadow-xl flex flex-col"
    >
      <div className="flex border-b border-border-subtle">
        {CATEGORIES.map((cat, i) => (
          <button
            key={cat.label}
            onClick={() => setActiveCat(i)}
            className={`flex-1 text-[10px] font-mono uppercase tracking-wider py-1.5 transition-colors ${
              activeCat === i
                ? "text-accent-400 border-b border-accent-400"
                : "text-text-tertiary hover:text-text-secondary"
            }`}
          >
            {cat.label}
          </button>
        ))}
      </div>
      <div className="grid grid-cols-8 gap-0.5 p-2 max-h-[260px] overflow-y-auto">
        {CATEGORIES[activeCat].emojis.map((e) => (
          <button
            key={e}
            onClick={() => onPick(e)}
            className="text-xl p-1 rounded hover:bg-bg-hover transition-colors"
          >
            {e}
          </button>
        ))}
      </div>
    </div>
  );
}
