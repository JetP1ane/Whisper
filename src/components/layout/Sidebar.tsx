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
  const [state, setState] = useState<"idle" | "copying" | "copied">("idle");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const copyInviteLink = async () => {
    setErrorMsg(null);
    setState("copying");
    try {
      const link = await invoke<string>("identity_invite_link");
      if (!link || typeof link !== "string") {
        throw new Error("invite link came back empty");
      }
      await navigator.clipboard.writeText(link);
      setState("copied");
      setTimeout(() => setState("idle"), 1500);
    } catch (e) {
      setErrorMsg(String(e));
      setState("idle");
      setTimeout(() => setErrorMsg(null), 3500);
    }
  };

  const label =
    state === "copying"
      ? "copying…"
      : state === "copied"
      ? "✓ copied to clipboard"
      : "copy invite link";

  return (
    <button
      onClick={copyInviteLink}
      title="Copies your whisper:// invite link. Paste it to anyone who wants to add you as a contact."
      className="w-full text-left px-2 py-1.5 rounded-md bg-bg-inset hover:bg-bg-hover transition-colors group"
    >
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          You
        </span>
        <span
          className={`text-[10px] font-mono uppercase tracking-wider transition-colors ${
            state === "copied"
              ? "text-status-ok"
              : "text-text-tertiary group-hover:text-accent-400"
          }`}
        >
          {label}
        </span>
      </div>
      <div className="font-mono text-xs text-text-primary truncate">
        {identity.alias}
      </div>
      {errorMsg && (
        <div className="mt-1 text-[10px] text-status-err break-words">
          {errorMsg}
        </div>
      )}
    </button>
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
