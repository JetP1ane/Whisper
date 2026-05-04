import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Conversation,
  useConversationStore,
} from "../../stores/conversationStore";

interface Props {
  conversation: Conversation;
  onClose: () => void;
}

const DISAPPEAR_OPTIONS: Array<{ label: string; secs: number | null }> = [
  { label: "Off", secs: null },
  { label: "30 seconds", secs: 30 },
  { label: "5 minutes", secs: 300 },
  { label: "1 hour", secs: 3600 },
  { label: "24 hours", secs: 86400 },
  { label: "7 days", secs: 604800 },
];

export function ConversationSettings({ conversation, onClose }: Props) {
  const loadConversations = useConversationStore((s) => s.loadConversations);
  const loadMessages = useConversationStore((s) => s.loadMessages);
  const selectConversation = useConversationStore((s) => s.selectConversation);

  const [nickname, setNickname] = useState(conversation.contact_nickname ?? "");
  const [savingNick, setSavingNick] = useState(false);
  const [nickErr, setNickErr] = useState<string | null>(null);

  const [disappear, setDisappear] = useState<number | null>(
    conversation.disappear_timer ?? null,
  );
  const [savingTimer, setSavingTimer] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const isRoom = conversation.kind === "room";
  const initialNickname = useMemo(
    () => conversation.contact_nickname ?? "",
    [conversation.contact_nickname],
  );
  const dirtyNick = nickname.trim() !== initialNickname.trim();

  useEffect(() => {
    setNickname(conversation.contact_nickname ?? "");
    setDisappear(conversation.disappear_timer ?? null);
  }, [conversation.id]);

  const saveNickname = async () => {
    if (!conversation.contact_id) return;
    setSavingNick(true);
    setNickErr(null);
    try {
      const trimmed = nickname.trim();
      await invoke("contact_set_nickname", {
        id: conversation.contact_id,
        nickname: trimmed.length > 0 ? trimmed : null,
      });
      await loadConversations();
      // Refresh the active message list so existing bubbles re-render with
      // the new nickname instead of the wire alias.
      await loadMessages(conversation.id);
    } catch (e) {
      setNickErr(String(e));
    } finally {
      setSavingNick(false);
    }
  };

  const setTimer = async (secs: number | null) => {
    setSavingTimer(true);
    try {
      await invoke("conversation_set_disappear", {
        conversationId: conversation.id,
        secs,
      });
      setDisappear(secs);
      await loadConversations();
    } finally {
      setSavingTimer(false);
    }
  };

  const onDelete = async () => {
    setDeleting(true);
    try {
      await invoke("conversation_delete", {
        conversationId: conversation.id,
      });
      selectConversation(null);
      await loadConversations();
      onClose();
    } finally {
      setDeleting(false);
      setConfirmingDelete(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center animate-fade-in"
      onClick={onClose}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-[480px] max-w-[90vw] panel border rounded-xl flex flex-col"
      >
        <header className="h-[44px] flex items-center justify-between px-4 border-b border-border-subtle">
          <span className="text-sm text-text-primary">
            {isRoom ? "Room settings" : "Conversation settings"}
          </span>
          <button onClick={onClose} className="btn-ghost text-xs">
            Close
          </button>
        </header>

        <div className="p-4 space-y-5 overflow-y-auto">
          {!isRoom && (
            <section className="space-y-2">
              <h3 className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
                Nickname
              </h3>
              <p className="text-xs text-text-secondary">
                Local-only display name. Their Whisper ID is{" "}
                <span className="font-mono text-text-primary">
                  {conversation.contact_alias ?? "—"}
                </span>
                . The peer never sees this nickname.
              </p>
              <div className="flex gap-2">
                <input
                  value={nickname}
                  onChange={(e) => setNickname(e.target.value)}
                  placeholder="Mark"
                  className="input flex-1"
                />
                <button
                  onClick={saveNickname}
                  disabled={savingNick || !dirtyNick}
                  className="btn-primary text-xs disabled:opacity-40"
                >
                  {savingNick ? "Saving…" : "Save"}
                </button>
              </div>
              {nickErr && (
                <div className="text-xs text-status-err">{nickErr}</div>
              )}
            </section>
          )}

          <section className="space-y-2">
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
              Disappearing messages
            </h3>
            <p className="text-xs text-text-secondary">
              Messages will be removed automatically after this window. Both
              sides enforce this independently — the timer is set per
              conversation.
            </p>
            <div className="grid grid-cols-3 gap-2">
              {DISAPPEAR_OPTIONS.map((opt) => {
                const active = (opt.secs ?? null) === (disappear ?? null);
                return (
                  <button
                    key={opt.label}
                    disabled={savingTimer}
                    onClick={() => setTimer(opt.secs)}
                    className={`px-2 py-1.5 rounded-md text-xs border transition-colors
                      ${
                        active
                          ? "bg-accent-500/10 border-accent-500/40 text-accent-300"
                          : "border-border-default text-text-primary hover:bg-bg-hover"
                      }`}
                  >
                    {opt.label}
                  </button>
                );
              })}
            </div>
          </section>

          <section className="space-y-2 pt-2 border-t border-border-subtle">
            <h3 className="text-[10px] font-mono uppercase tracking-wider text-status-err">
              Danger zone
            </h3>
            {!confirmingDelete ? (
              <button
                onClick={() => setConfirmingDelete(true)}
                className="btn w-full bg-status-err/10 text-status-err border border-status-err/30 hover:bg-status-err/20 text-xs"
              >
                {isRoom ? "Leave and delete room" : "Delete conversation"}
              </button>
            ) : (
              <div className="space-y-2">
                <p className="text-[11px] text-text-secondary leading-snug">
                  {isRoom
                    ? "Removes the room and every message locally. Other members are not notified."
                    : "Removes the contact, the conversation, every message, and the ratchet session. Cannot be undone."}
                </p>
                <div className="flex gap-2">
                  <button
                    onClick={() => setConfirmingDelete(false)}
                    disabled={deleting}
                    className="btn-ghost flex-1 text-xs"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={onDelete}
                    disabled={deleting}
                    className="btn flex-1 bg-status-err text-white border border-status-err hover:bg-status-err/90 text-xs disabled:opacity-40"
                  >
                    {deleting ? "Deleting…" : "Delete"}
                  </button>
                </div>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
