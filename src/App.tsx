import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { vaultLock, publishBundle } from "./hooks/useCrypto";
import { TitleBar } from "./components/layout/TitleBar";
import { Sidebar } from "./components/layout/Sidebar";
import { ChatView } from "./components/layout/ChatView";
import { InfoPanel } from "./components/layout/InfoPanel";
import { I2pBootstrapBanner } from "./components/layout/I2pBootstrapBanner";
import { VaultLock } from "./components/vault/VaultLock";
import { VaultSetup } from "./components/vault/VaultSetup";
import { OnboardingFlow } from "./components/vault/OnboardingFlow";
import { QuickSearch } from "./components/shared/QuickSearch";
import { Settings } from "./components/settings/Settings";
import { useKeyboard } from "./hooks/useKeyboard";
import { useAppStore } from "./stores/appStore";
import { useConversationStore } from "./stores/conversationStore";

interface MessageReceivedPayload {
  conversation_id: string;
  sender_alias: string;
  preview: string | null;
  is_attachment: boolean;
}

type Phase = "loading" | "intro" | "setup" | "alias_reveal" | "locked" | "ready";

export default function App() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [quickSearchOpen, setQuickSearchOpen] = useState(false);
  const [infoOpen, setInfoOpen] = useState(true);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const refreshStatus = useAppStore((s) => s.refreshStatus);

  useEffect(() => {
    (async () => {
      const status = await refreshStatus();
      if (!status.initialized) setPhase("intro");
      else if (!status.unlocked) setPhase("locked");
      else setPhase("ready");
    })();
  }, [refreshStatus]);

  // Publish our bundle once we're in a usable phase. With the I2P
  // transport this is purely informational on the local DB — peers
  // discover us via QR/whisper:// link, not a relay-side directory.
  useEffect(() => {
    if (phase !== "ready" && phase !== "alias_reveal") return;
    let cancelled = false;
    (async () => {
      try {
        await publishBundle();
      } catch (e) {
        if (!cancelled) console.warn("publishBundle failed:", e);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [phase]);

  // Listen for backend events and refresh sidebar / active conversation.
  const loadConversations = useConversationStore((s) => s.loadConversations);
  const selectedId = useConversationStore((s) => s.selectedId);
  const loadMessages = useConversationStore((s) => s.loadMessages);
  useEffect(() => {
    const unlistens: Array<() => void> = [];
    listen<MessageReceivedPayload>("message:received", (e) => {
      const convId = e.payload.conversation_id;
      loadConversations();
      if (selectedId === convId) loadMessages(convId);
    }).then((u) => unlistens.push(u));
    listen<{ sender_alias: string; conversation_id: string }>(
      "contact:received",
      () => loadConversations(),
    ).then((u) => unlistens.push(u));
    listen<{ message_id: string; status: string }>("message:status", () => {
      if (selectedId) loadMessages(selectedId);
    }).then((u) => unlistens.push(u));
    listen<number>("messages:purged", () => {
      loadConversations();
      if (selectedId) loadMessages(selectedId);
    }).then((u) => unlistens.push(u));
    listen<unknown>("rooms:changed", () => {
      loadConversations();
    }).then((u) => unlistens.push(u));
    return () => {
      for (const u of unlistens) u();
    };
  }, [selectedId, loadConversations, loadMessages]);

  useKeyboard({
    onCmdK: () => setQuickSearchOpen((v) => !v),
    onCmdL: async () => {
      await vaultLock();
      setPhase("locked");
    },
  });

  return (
    <div className="h-screen w-screen flex flex-col bg-bg-base text-text-primary">
      <TitleBar
        onOpenSettings={() => setSettingsOpen(true)}
        onLock={
          phase === "ready"
            ? async () => {
                await vaultLock();
                setPhase("locked");
              }
            : undefined
        }
      />
      {phase === "ready" && <I2pBootstrapBanner />}
      <div className="flex-1 min-h-0 flex">
        {phase === "loading" && <LoadingShell />}

        {phase === "intro" && (
          <OnboardingFlow onContinue={() => setPhase("setup")} />
        )}

        {phase === "setup" && (
          <VaultSetup
            onComplete={async () => {
              await refreshStatus();
              setPhase("alias_reveal");
            }}
          />
        )}

        {phase === "alias_reveal" && (
          <OnboardingFlow showAlias onContinue={() => setPhase("ready")} />
        )}

        {phase === "locked" && (
          <VaultLock
            onUnlock={async () => {
              await refreshStatus();
              setPhase("ready");
            }}
          />
        )}

        {phase === "ready" && (
          <>
            <Sidebar />
            <ChatView onToggleInfo={() => setInfoOpen((v) => !v)} />
            {infoOpen && <InfoPanel />}
          </>
        )}
      </div>
      {quickSearchOpen && phase === "ready" && (
        <QuickSearch onClose={() => setQuickSearchOpen(false)} />
      )}
      {settingsOpen && phase === "ready" && (
        <Settings onClose={() => setSettingsOpen(false)} />
      )}
    </div>
  );
}

function LoadingShell() {
  return (
    <div className="flex-1 flex items-center justify-center">
      <div className="text-text-tertiary text-sm tracking-wide">noctis</div>
    </div>
  );
}
