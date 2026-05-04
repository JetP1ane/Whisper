import { useState } from "react";
import { useConversationStore, conversationLabel } from "../../stores/conversationStore";
import { acceptContactRequest, declineContactRequest } from "../../hooks/useCrypto";

export function RequestList() {
  const conversations = useConversationStore((s) => s.conversations);
  const loadConversations = useConversationStore((s) => s.loadConversations);
  const [busyId, setBusyId] = useState<string | null>(null);

  const pending = conversations.filter(
    (c) => c.kind === "direct" && c.is_pending,
  );

  if (pending.length === 0) return null;

  return (
    <div className="flex flex-col px-1">
      {pending.map((c) => {
        const label = conversationLabel(c);
        return (
          <div
            key={c.id}
            className="px-3 py-2 mx-1 my-0.5 rounded-md border border-accent-500/20 bg-accent-500/5 flex items-center gap-2"
          >
            <div className="flex-1 min-w-0">
              <div className="text-[10px] font-mono uppercase tracking-wider text-accent-400">
                Wants to chat
              </div>
              <div className="text-sm text-text-primary truncate font-mono">
                {label}
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button
                disabled={busyId === c.id}
                onClick={async () => {
                  setBusyId(c.id);
                  try {
                    await declineContactRequest(c.id);
                  } finally {
                    setBusyId(null);
                    loadConversations();
                  }
                }}
                className="btn-ghost text-[11px] px-2"
                title="Decline"
              >
                ✕
              </button>
              <button
                disabled={busyId === c.id}
                onClick={async () => {
                  setBusyId(c.id);
                  try {
                    await acceptContactRequest(c.id);
                  } finally {
                    setBusyId(null);
                    loadConversations();
                  }
                }}
                className="btn-primary text-[11px] px-2"
                title="Accept"
              >
                ✓
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
