import { useEffect, useRef, useState } from "react";
import { useConversationStore, conversationLabel } from "../../stores/conversationStore";
import { MessageBubble } from "../chat/MessageBubble";
import { ComposeBar } from "../chat/ComposeBar";
import { ConversationSettings } from "../chat/ConversationSettings";

interface Props {
  onToggleInfo: () => void;
}

export function ChatView({ onToggleInfo }: Props) {
  const selected = useConversationStore((s) => s.selectedId);
  const conversations = useConversationStore((s) => s.conversations);
  const messages = useConversationStore((s) => s.messages);
  const send = useConversationStore((s) => s.send);
  const sendDetonating = useConversationStore((s) => s.sendDetonating);
  const sendAttachment = useConversationStore((s) => s.sendAttachment);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [showSettings, setShowSettings] = useState(false);

  const conv = conversations.find((c) => c.id === selected);

  useEffect(() => {
    scrollRef.current?.scrollTo({
      top: scrollRef.current.scrollHeight,
      behavior: "instant" as ScrollBehavior,
    });
  }, [messages.length, selected]);

  if (!selected || !conv) return <EmptyState />;

  const isDirect = conv.kind === "direct";
  const hasNickname = isDirect && !!conv.contact_nickname;

  return (
    <main className="flex-1 min-w-0 flex flex-col bg-bg-base">
      <header className="h-[44px] flex items-center justify-between px-4 border-b border-border-subtle">
        <div className="min-w-0">
          <div
            className={`text-sm text-text-primary truncate ${
              hasNickname ? "" : "font-mono"
            }`}
          >
            {conversationLabel(conv)}
          </div>
          {hasNickname && (
            <div className="text-[10px] font-mono text-text-tertiary truncate">
              {conv.contact_alias}
            </div>
          )}
          {conv.is_sealed && (
            <div className="text-[10px] font-mono uppercase tracking-wider text-accent-400">
              sealed
            </div>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setShowSettings(true)}
            className="btn-ghost p-1 text-text-tertiary hover:text-text-primary"
            title="Conversation settings"
          >
            <SettingsIcon />
          </button>
          <button onClick={onToggleInfo} className="btn-ghost text-xs">
            Info
          </button>
        </div>
      </header>

      {showSettings && (
        <ConversationSettings
          conversation={conv}
          onClose={() => setShowSettings(false)}
        />
      )}

      <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-3 space-y-1">
        {messages.length === 0 ? (
          <div className="text-center text-text-tertiary text-xs pt-6">
            No messages yet.
          </div>
        ) : (
          messages.map((m) => <MessageBubble key={m.id} m={m} />)
        )}
      </div>

      <ComposeBar
        onSend={(text, detonateSecs) => {
          if (!text.trim()) return;
          if (detonateSecs && conv.kind === "direct") {
            sendDetonating(selected, text, detonateSecs);
          } else {
            send(selected, text);
          }
        }}
        onSendAttachment={(path) => sendAttachment(selected, path)}
      />
    </main>
  );
}

function EmptyState() {
  return (
    <main className="flex-1 flex flex-col items-center justify-center bg-bg-base">
      <div className="text-text-tertiary text-sm">Select a conversation</div>
      <div className="mt-2 text-text-tertiary text-xs">
        <span className="kbd">⌘K</span> <span className="ml-1">to search</span>
      </div>
    </main>
  );
}

function SettingsIcon() {
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
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}
