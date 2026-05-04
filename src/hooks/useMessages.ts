import { useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";

export function useMessages(conversationId: string | null) {
  const send = useCallback(
    async (text: string) => {
      if (!conversationId) return;
      return invoke<string>("message_send", { conversationId, text });
    },
    [conversationId],
  );

  const sendAttachment = useCallback(
    async (sourcePath: string) => {
      if (!conversationId) return;
      return invoke<string>("message_send_attachment", {
        conversationId,
        sourcePath,
      });
    },
    [conversationId],
  );

  return { send, sendAttachment };
}
