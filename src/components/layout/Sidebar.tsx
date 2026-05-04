import { useEffect, useState } from "react";
import { ContactList } from "../contacts/ContactList";
import { RequestList } from "../contacts/RequestList";
import { RoomList } from "../rooms/RoomList";
import { AddContact } from "../contacts/AddContact";
import { CreateRoom } from "../rooms/CreateRoom";
import { useConversationStore } from "../../stores/conversationStore";
import { getIdentity, IdentitySummary } from "../../hooks/useCrypto";

export function Sidebar() {
  const loadConversations = useConversationStore((s) => s.loadConversations);
  const selectConversation = useConversationStore((s) => s.selectConversation);
  const [identity, setIdentity] = useState<IdentitySummary | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [showCreateRoom, setShowCreateRoom] = useState(false);

  useEffect(() => {
    loadConversations();
    getIdentity().then(setIdentity).catch(() => {});
  }, [loadConversations]);

  const hasPending = useConversationStore(
    (s) => s.conversations.some((c) => c.kind === "direct" && c.is_pending),
  );

  return (
    <aside className="w-[260px] flex-shrink-0 flex flex-col bg-bg-panel border-r border-border-subtle">
      {hasPending && (
        <>
          <SectionHeader label="Requests" />
          <RequestList />
        </>
      )}

      <SectionHeader
        label="Direct messages"
        actionLabel="+"
        onAction={() => setShowAdd(true)}
        hint="⌘N"
      />
      <ContactList />

      <SectionHeader
        label="Rooms"
        actionLabel="+"
        hint="⌘⇧N"
        onAction={() => setShowCreateRoom(true)}
        className="mt-2"
      />
      <RoomList />

      <div className="mt-auto p-3 border-t border-border-subtle space-y-2">
        {identity && <IdentityCard identity={identity} />}
        <RelayPill />
      </div>

      {showAdd && (
        <AddContactModal onClose={() => setShowAdd(false)} onAdded={() => {
          setShowAdd(false);
          loadConversations();
        }} />
      )}
      {showCreateRoom && (
        <CreateRoomModal
          onClose={() => setShowCreateRoom(false)}
          onCreated={async (id) => {
            setShowCreateRoom(false);
            await loadConversations();
            selectConversation(id);
          }}
        />
      )}
    </aside>
  );
}

function CreateRoomModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (id: string) => void;
}) {
  return (
    <div
      onClick={onClose}
      className="fixed inset-0 z-40 bg-black/60 flex items-center justify-center animate-fade-in"
    >
      <div onClick={(e) => e.stopPropagation()} className="w-[420px] panel border rounded-xl">
        <CreateRoom onCreated={onCreated} onCancel={onClose} />
      </div>
    </div>
  );
}

function SectionHeader({
  label,
  hint,
  actionLabel,
  onAction,
  className = "",
}: {
  label: string;
  hint?: string;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}) {
  return (
    <div
      className={`flex items-center justify-between px-4 pt-3 pb-1 ${className}`}
    >
      <span className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
        {label}
      </span>
      <div className="flex items-center gap-1">
        {actionLabel && (
          <button
            onClick={onAction}
            className="kbd hover:bg-bg-active hover:text-text-primary cursor-pointer transition-colors"
            title={`Add (${hint ?? ""})`}
          >
            {actionLabel}
          </button>
        )}
        {hint && !actionLabel && <span className="kbd">{hint}</span>}
      </div>
    </div>
  );
}

function IdentityCard({ identity }: { identity: IdentitySummary }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(identity.alias);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* ignore */
    }
  };
  return (
    <button
      onClick={onCopy}
      title="Click to copy your Whisper ID"
      className="w-full text-left px-2 py-1.5 rounded-md bg-bg-inset hover:bg-bg-hover transition-colors"
    >
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          You
        </span>
        <span className="text-[10px] font-mono uppercase tracking-wider text-accent-400 transition-opacity"
              style={{ opacity: copied ? 1 : 0 }}>
          copied
        </span>
      </div>
      <div className="font-mono text-xs text-text-primary truncate">
        {identity.alias}
      </div>
    </button>
  );
}

function RelayPill() {
  return (
    <div className="flex items-center gap-2 px-2 py-1.5 rounded-md bg-bg-inset">
      <span className="w-1.5 h-1.5 rounded-full bg-status-ok shrink-0" />
      <span className="text-xs text-text-secondary truncate">relay.local</span>
    </div>
  );
}

function AddContactModal({
  onClose,
  onAdded,
}: {
  onClose: () => void;
  onAdded: () => void;
}) {
  return (
    <div
      onClick={onClose}
      className="fixed inset-0 z-40 bg-black/60 flex items-center justify-center animate-fade-in"
    >
      <div onClick={(e) => e.stopPropagation()} className="w-[420px] panel border rounded-xl">
        <AddContact onAdded={onAdded} onCancel={onClose} />
      </div>
    </div>
  );
}
