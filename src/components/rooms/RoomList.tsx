import { useConversationStore } from "../../stores/conversationStore";

export function RoomList() {
  const conversations = useConversationStore((s) => s.conversations);
  const select = useConversationStore((s) => s.selectConversation);
  const selectedId = useConversationStore((s) => s.selectedId);

  const rooms = conversations.filter((c) => c.kind === "room");
  if (rooms.length === 0) {
    return (
      <div className="px-4 py-2 text-[11px] text-text-tertiary italic">
        Create a room to chat with multiple people
      </div>
    );
  }
  return (
    <div className="flex flex-col px-1">
      {rooms.map((c) => (
        <button
          key={c.id}
          onClick={() => select(c.id)}
          className={`flex items-center gap-2 px-3 py-2 rounded-md text-left
            ${selectedId === c.id ? "bg-gray-800" : "hover:bg-bg-hover"}`}
        >
          <span className="w-7 h-7 rounded-md bg-bg-active border border-border-subtle flex items-center justify-center text-[11px] text-text-secondary">
            #
          </span>
          <div className="flex-1 min-w-0">
            <div className="text-sm text-text-primary truncate">{c.room_name}</div>
            <div className="text-[11px] text-text-tertiary truncate">
              {c.unread_count > 0 ? `${c.unread_count} new` : "-"}
            </div>
          </div>
          {c.unread_count > 0 && (
            <span className="min-w-[18px] h-[18px] px-1 rounded-full bg-accent-500 text-black text-[10px] font-mono font-bold flex items-center justify-center">
              {c.unread_count > 99 ? "99+" : c.unread_count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}
