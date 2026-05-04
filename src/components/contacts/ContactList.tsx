import { useConversationStore, conversationLabel } from "../../stores/conversationStore";
import { aliasInitials, formatTime } from "../../utils/formatters";

export function ContactList() {
  const conversations = useConversationStore((s) => s.conversations);
  const selectedId = useConversationStore((s) => s.selectedId);
  const select = useConversationStore((s) => s.selectConversation);

  const directs = conversations.filter((c) => c.kind === "direct" && !c.is_pending);

  if (directs.length === 0) {
    return <EmptyHint label="Add a contact by alias to begin" />;
  }

  return (
    <div className="flex flex-col px-1">
      {directs.map((c) => {
        const label = conversationLabel(c);
        return (
        <button
          key={c.id}
          onClick={() => select(c.id)}
          className={`flex items-center gap-2 px-3 py-2 rounded-md text-left
            ${selectedId === c.id ? "bg-bg-active" : "hover:bg-bg-hover"}`}
        >
          <Avatar alias={label} />
          <div className="flex-1 min-w-0">
            <div className="text-sm text-text-primary truncate font-mono">
              {label}
            </div>
            <div className="text-[11px] text-text-tertiary truncate">
              {c.last_message_at ? formatTime(c.last_message_at) : "no messages yet"}
            </div>
          </div>
          {c.unread_count > 0 && (
            <span className="min-w-[18px] h-[18px] px-1 rounded-full bg-accent-500 text-black text-[10px] font-mono font-bold flex items-center justify-center">
              {c.unread_count > 99 ? "99+" : c.unread_count}
            </span>
          )}
        </button>
        );
      })}
    </div>
  );
}

function Avatar({ alias }: { alias: string }) {
  return (
    <div className="w-7 h-7 rounded-md bg-bg-active border border-border-subtle flex items-center justify-center">
      <span className="text-[10px] font-mono text-text-secondary">
        {aliasInitials(alias)}
      </span>
    </div>
  );
}

function EmptyHint({ label }: { label: string }) {
  return (
    <div className="px-4 py-2 text-[11px] text-text-tertiary italic">
      {label}
    </div>
  );
}
