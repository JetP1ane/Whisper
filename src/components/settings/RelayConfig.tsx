import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

export function RelayConfig() {
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    invoke<{ url: string | null }>("relay_status")
      .then((r) => setUrl(r.url ?? ""))
      .catch(() => {});
  }, []);

  const save = async () => {
    setBusy(true);
    setStatus(null);
    try {
      await invoke("relay_change_url", { newUrl: url });
      setStatus("Connected. Contacts have been notified of the new relay.");
    } catch (e) {
      setStatus(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="space-y-2">
      <h3 className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
        Relay
      </h3>
      <p className="text-xs text-text-secondary">
        Use the default relay or host your own. Changing this requires Touch ID — the new URL is
        included in the signed configuration manifest.
      </p>
      <input
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="wss://relay.example.com"
        className="input font-mono"
      />
      <div className="flex justify-between items-center">
        <span className="text-[11px] text-text-tertiary">{status}</span>
        <button
          disabled={busy || !url}
          onClick={save}
          className="btn-primary text-xs disabled:opacity-40"
        >
          {busy ? "Saving…" : "Save"}
        </button>
      </div>
    </section>
  );
}
