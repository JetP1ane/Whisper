// Placeholder — actual WebSocket lifecycle lives in Rust (see
// `src-tauri/src/transport/relay.rs`). The frontend listens to Tauri events
// emitted by the relay reader task. This hook is a thin wrapper around those
// events for components that need them.

import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";

export interface RelayEvent {
  kind: "notify" | "deposited" | "retrieved" | "error";
  data?: unknown;
}

export function useRelayEvents(handler: (e: RelayEvent) => void) {
  useEffect(() => {
    const unlistenPromises = [
      listen<RelayEvent>("relay:notify", (e) => handler({ kind: "notify", data: e.payload })),
      listen<RelayEvent>("relay:deposited", (e) => handler({ kind: "deposited", data: e.payload })),
      listen<RelayEvent>("relay:retrieved", (e) => handler({ kind: "retrieved", data: e.payload })),
      listen<RelayEvent>("relay:error", (e) => handler({ kind: "error", data: e.payload })),
    ];
    return () => {
      unlistenPromises.forEach((p) => p.then((unlisten) => unlisten()));
    };
  }, [handler]);
}

export function useRelayConnected() {
  const [connected, setConnected] = useState(false);
  useRelayEvents((e) => {
    if (e.kind === "error") setConnected(false);
    if (e.kind === "notify" || e.kind === "retrieved") setConnected(true);
  });
  return connected;
}
