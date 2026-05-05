import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
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
  const [copied, setCopied] = useState<"alias" | "invite" | null>(null);

  const copyAlias = async () => {
    try {
      await navigator.clipboard.writeText(identity.alias);
      setCopied("alias");
      setTimeout(() => setCopied(null), 1200);
    } catch {
      /* ignore */
    }
  };

  const copyInvite = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const link = await invoke<string>("identity_invite_link");
      await navigator.clipboard.writeText(link);
      setCopied("invite");
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="w-full px-2 py-1.5 rounded-md bg-bg-inset">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          You
        </span>
        <span
          className="text-[10px] font-mono uppercase tracking-wider text-accent-400 transition-opacity"
          style={{ opacity: copied !== null ? 1 : 0 }}
        >
          {copied === "invite" ? "invite copied" : copied === "alias" ? "id copied" : "copied"}
        </span>
      </div>
      <button
        onClick={copyAlias}
        title="Click to copy your three-word Whisper ID"
        className="block w-full text-left font-mono text-xs text-text-primary truncate hover:text-accent-400 transition-colors"
      >
        {identity.alias}
      </button>
      <button
        onClick={copyInvite}
        title="Copy your whisper:// invite link to share with someone who wants to add you"
        className="mt-1.5 w-full px-2 py-1 rounded-md bg-accent-500/15 hover:bg-accent-500/25 border border-accent-500/30 transition-colors text-[11px] font-mono text-accent-400 flex items-center justify-center gap-1"
      >
        <ShareIcon /> share invite link
      </button>
    </div>
  );
}

function ShareIcon() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8" />
      <polyline points="16 6 12 2 8 6" />
      <line x1="12" y1="2" x2="12" y2="15" />
    </svg>
  );
}

interface I2pStatusPill {
  ready: boolean;
  destination: string;
  cached_outbound_streams: number;
}

function RelayPill() {
  const [i2p, setI2p] = useState<I2pStatusPill | null>(null);

  useEffect(() => {
    const tick = async () => {
      try {
        setI2p(await invoke<I2pStatusPill>("i2p_status"));
      } catch {
        /* ignore */
      }
    };
    tick();
    const t = setInterval(tick, 5_000);
    return () => clearInterval(t);
  }, []);

  const ready = i2p?.ready ?? false;
  const label = ready
    ? `i2p · ${i2p?.cached_outbound_streams ?? 0} streams`
    : "i2p starting…";
  const dotClass = ready ? "bg-status-ok" : "bg-status-warn";

  return (
    <div
      className="flex items-center gap-2 px-2 py-1.5 rounded-md bg-bg-inset"
      title="Peer-to-peer transport over I2P (encrypted leasesets)"
    >
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotClass}`} />
      <span className="text-xs text-text-secondary truncate font-mono">{label}</span>
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
