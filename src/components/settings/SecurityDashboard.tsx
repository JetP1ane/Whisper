import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { vaultViewRecoveryPhrase } from "../../hooks/useCrypto";

interface Snapshot {
  frames_sent: number;
  frames_received: number;
  bytes_sent: number;
  bytes_received: number;
}

interface SecurityStatus {
  vault_unlocked: boolean;
  hardware_tier: string;
  relay_connected: boolean;
  relay_url: string | null;
  frame_counters: Snapshot;
}

export function SecurityDashboard() {
  const [status, setStatus] = useState<SecurityStatus | null>(null);

  useEffect(() => {
    const tick = async () => {
      try {
        setStatus(await invoke<SecurityStatus>("security_status"));
      } catch {
        /* ignore */
      }
    };
    tick();
    const t = setInterval(tick, 10_000);
    return () => clearInterval(t);
  }, []);

  if (!status) return <div className="text-xs text-text-tertiary">Loading…</div>;

  return (
    <section className="space-y-4">
      <div>
        <h3 className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary mb-2">
          Security dashboard
        </h3>
        <div className="grid grid-cols-2 gap-2">
          <Card label="Vault" ok={status.vault_unlocked} value={status.vault_unlocked ? "Unlocked" : "Locked"} />
          <Card label="Hardware" ok={status.hardware_tier !== "none"} value={prettyTier(status.hardware_tier)} />
          <Card label="Relay" ok={status.relay_connected} value={status.relay_url ?? "—"} />
          <Card
            label="Frames"
            ok
            value={`${status.frame_counters.frames_sent} ↑ / ${status.frame_counters.frames_received} ↓`}
            mono
          />
        </div>
      </div>
      <RecoveryPhraseRow />
    </section>
  );
}

function RecoveryPhraseRow() {
  const [pass, setPass] = useState("");
  const [phrase, setPhrase] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  const reveal = async () => {
    setBusy(true);
    setErr(null);
    try {
      const p = await vaultViewRecoveryPhrase(pass);
      if (!p) {
        setErr("This vault was created before recovery phrases. Re-create the vault to enable recovery.");
      } else {
        setPhrase(p);
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h3 className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary mb-2">
        Recovery phrase
      </h3>
      <p className="text-xs text-text-secondary leading-relaxed mb-3">
        12 words that can re-derive your Whisper ID and identity keys on a new
        device. Anyone with these words can take over your account — store them
        offline.
      </p>

      {phrase ? (
        <RecoveryPhraseDisplay phrase={phrase} onHide={() => setPhrase(null)} />
      ) : !confirming ? (
        <button
          onClick={() => setConfirming(true)}
          className="btn-secondary text-xs"
        >
          Show recovery phrase
        </button>
      ) : (
        <div className="space-y-2">
          <p className="text-[11px] text-text-secondary leading-snug">
            Re-enter your vault passphrase to reveal your 12 words.
          </p>
          <input
            autoFocus
            type="password"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && reveal()}
            placeholder="Passphrase"
            className="input"
          />
          {err && <div className="text-xs text-status-err">{err}</div>}
          <div className="flex gap-2">
            <button
              onClick={() => {
                setConfirming(false);
                setPass("");
                setErr(null);
              }}
              disabled={busy}
              className="btn-ghost flex-1 text-xs"
            >
              Cancel
            </button>
            <button
              onClick={reveal}
              disabled={busy || pass.length === 0}
              className="btn-primary flex-1 text-xs disabled:opacity-40"
            >
              {busy ? "Verifying…" : "Reveal"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function RecoveryPhraseDisplay({ phrase, onHide }: { phrase: string; onHide: () => void }) {
  const [copied, setCopied] = useState(false);
  const words = phrase.split(/\s+/);
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-3 gap-2 px-2 py-3 rounded-md bg-bg-inset border border-border-subtle">
        {words.map((w, i) => (
          <div key={i} className="flex items-baseline gap-1.5">
            <span className="text-[10px] font-mono text-text-tertiary tabular-nums w-4 text-right">
              {i + 1}
            </span>
            <span className="text-[13px] font-mono text-text-primary">{w}</span>
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <button
          onClick={async () => {
            await navigator.clipboard.writeText(phrase);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
          className="btn-secondary text-xs"
        >
          {copied ? "Copied" : "Copy"}
        </button>
        <button onClick={onHide} className="btn-ghost text-xs">
          Hide
        </button>
      </div>
    </div>
  );
}

function Card({
  label,
  ok,
  value,
  mono,
}: {
  label: string;
  ok: boolean;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="panel border rounded-md p-3">
      <div className="flex items-center gap-1.5 mb-1">
        <span className={`w-1.5 h-1.5 rounded-full ${ok ? "bg-status-ok" : "bg-status-err"}`} />
        <span className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">{label}</span>
      </div>
      <div className={`text-xs text-text-primary ${mono ? "font-mono" : ""}`}>{value}</div>
    </div>
  );
}

function prettyTier(t: string) {
  switch (t) {
    case "secure_enclave_biometric":
      return "Secure Enclave + Touch ID";
    case "secure_enclave":
      return "Secure Enclave";
    case "software_only":
      return "Software";
    default:
      return "—";
  }
}
