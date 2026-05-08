import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";

export interface Conversation {
  id: string;
  kind: "direct" | "room";
  contact_id: string | null;
  contact_alias: string | null;
  contact_nickname: string | null;
  room_name: string | null;
  room_description: string | null;
  disappear_timer: number | null;
  is_sealed: boolean;
  is_pending: boolean;
  last_message_at: number | null;
  unread_count: number;
  created_at: number;
}

/** Display label used in the sidebar / chat header. Prefers a user-set
 *  nickname over the wire alias. */
export function conversationLabel(c: Conversation): string {
  if (c.kind === "room") return c.room_name ?? "Room";
  return c.contact_nickname ?? c.contact_alias ?? "Unknown";
}

export interface DisplayMessage {
  id: string;
  conversation_id: string;
  sender_alias: string;
  sender_nickname: string | null;
  is_outbound: boolean;
  text: string | null;
  is_attachment: boolean;
  filename: string | null;
  mime_type: string | null;
  file_size: number | null;
  status: string;
  /** Unix-ms deadline at which the client should detonate this message
   *  locally. Set when the sender opted in to a self-detonating envelope
   *  or when the conversation has a disappear timer. */
  disappear_at: number | null;
  /** Which transport carried this outbound message — `"i2p"` or
   *  `"relay"`. `null` for inbound rows or pre-Phase-6 sends. The
   *  bubble renders a small icon distinguishing them. */
  delivery_transport: string | null;
  /** Number of times the I2P send-queue worker has retried delivery.
   *  Non-null only for outbound queued rows currently in the queue. */
  attempt_count: number | null;
  /** Unix-ms of the last delivery attempt, or null if never attempted. */
  last_attempt_at: number | null;
  /** Emoji reactions on this message, grouped per emoji. */
  reactions: ReactionGroup[];
  created_at: number;
}

export interface ReactionGroup {
  emoji: string;
  count: number;
  /** True iff *this* device contributed at least one of the count. */
  mine: boolean;
}

interface State {
  conversations: Conversation[];
  selectedId: string | null;
  messages: DisplayMessage[];
  loadConversations: () => Promise<void>;
  selectConversation: (id: string | null) => void;
  loadMessages: (conversationId: string) => Promise<void>;
  send: (conversationId: string, text: string) => Promise<void>;
  sendDetonating: (
    conversationId: string,
    text: string,
    detonateSecs: number,
  ) => Promise<void>;
  sendAttachment: (conversationId: string, sourcePath: string) => Promise<void>;
}

export const useConversationStore = create<State>((set, get) => ({
  conversations: [],
  selectedId: null,
  messages: [],
  loadConversations: async () => {
    try {
      const list = await invoke<Conversation[]>("conversation_list");
      set({ conversations: list });
    } catch {
      set({ conversations: [] });
    }
  },
  selectConversation: (id) => {
    if (id) {
      // Optimistic clear so the green badge disappears instantly on
      // click instead of waiting for the backend roundtrip + the
      // `conversations:changed` event. The backend mark_read still
      // runs for durability — if it fails the worst that happens is
      // the badge re-appears on the next loadConversations.
      const prev = get().conversations;
      const cleared = prev.map((c) =>
        c.id === id && c.unread_count > 0 ? { ...c, unread_count: 0 } : c,
      );
      set({ selectedId: id, messages: [], conversations: cleared });
      get().loadMessages(id);
      invoke("conversation_mark_read", { conversationId: id }).catch(() => {});
    } else {
      set({ selectedId: id, messages: [] });
    }
  },
  loadMessages: async (conversationId) => {
    try {
      const msgs = await invoke<DisplayMessage[]>("conversation_messages", {
        conversationId,
      });
      set({ messages: msgs });
    } catch {
      set({ messages: [] });
    }
  },
  send: async (conversationId, text) => {
    const conv = get().conversations.find((c) => c.id === conversationId);
    if (conv?.kind === "room") {
      await invoke<string>("room_send", { roomId: conversationId, text });
    } else {
      await invoke<string>("message_send", { conversationId, text });
    }
    await get().loadMessages(conversationId);
  },
  sendDetonating: async (conversationId, text, detonateSecs) => {
    await invoke<string>("message_send_detonating", {
      conversationId,
      text,
      detonateSecs,
    });
    await get().loadMessages(conversationId);
  },
  sendAttachment: async (conversationId, sourcePath) => {
    await invoke<string>("message_send_attachment", {
      conversationId,
      sourcePath,
    });
    await get().loadMessages(conversationId);
  },
}));
