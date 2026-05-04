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

interface I2pStatus {
  ready: boolean;
  destination: string;
  session_id: string;
  sam_addr: string;
  log_path: string;
  cached_outbound_streams: number;
}

export function SecurityDashboard() {
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  const [i2p, setI2p] = useState<I2pStatus | null>(null);

  useEffect(() => {
    const tick = async () => {
      try {
        setStatus(await invoke<SecurityStatus>("security_status"));
      } catch {
        /* ignore */
      }
      try {
        setI2p(await invoke<I2pStatus>("i2p_status"));
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
          <Card
            label="I2P"
            ok={i2p?.ready ?? false}
            value={i2p?.ready ? `Connected (${i2p.cached_outbound_streams} streams)` : "Starting…"}
          />
          <Card label="Relay (fallback)" ok={status.relay_connected} value={status.relay_url ?? "—"} />
        </div>
        {i2p?.ready && (
          <div className="mt-3 p-3 rounded-md bg-bg-inset border border-border-subtle space-y-1">
            <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
              I2P destination
            </div>
            <div className="text-[10px] font-mono text-text-secondary break-all leading-relaxed">
              {i2p.destination}
            </div>
            <div className="mt-2 text-[10px] text-text-tertiary">
              SAM: <span className="font-mono">{i2p.sam_addr}</span> · Session:{" "}
              <span className="font-mono">{i2p.session_id.slice(0, 12)}…</span>
            </div>
          </div>
        )}
        <I2pOnlyModeRow />
        <TransitOptInRow />
      </div>
      <RecoveryPhraseRow />
    </section>
  );
}

function I2pOnlyModeRow() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    invoke<boolean>("i2p_get_only_mode")
      .then(setEnabled)
      .catch(() => setEnabled(false));
  }, []);

  const toggle = async () => {
    if (saving || enabled === null) return;
    setSaving(true);
    const next = !enabled;
    try {
      await invoke("i2p_set_only_mode", { enabled: next });
      setEnabled(next);
    } catch {
      /* keep previous */
    } finally {
      setSaving(false);
    }
  };

  if (enabled === null) return null;
  return (
    <div className="mt-3 p-3 rounded-md bg-bg-inset border border-border-subtle">
      <label className="flex items-start gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={enabled}
          onChange={toggle}
          disabled={saving}
          className="mt-0.5"
        />
        <span className="flex-1 text-[11px] text-text-secondary leading-snug">
          <span className="block text-text-primary">
            I2P only &mdash; disable relay fallback
          </span>
          <span className="block mt-0.5">
            Sends only attempt I2P. If I2P can&rsquo;t reach the peer, the
            message is marked failed instead of being carried by the
            relay. Useful for testing the I2P transport in isolation.
            Keep this off in normal use so messages still get through
            during the I2P bootstrap window.
          </span>
        </span>
      </label>
    </div>
  );
}

function TransitOptInRow() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    invoke<boolean>("i2p_get_transit_optin")
      .then(setEnabled)
      .catch(() => setEnabled(false));
  }, []);

  const toggle = async () => {
    if (saving || enabled === null) return;
    setSaving(true);
    const next = !enabled;
    try {
      await invoke("i2p_set_transit_optin", { enabled: next });
      setEnabled(next);
    } catch {
      /* keep previous */
    } finally {
      setSaving(false);
    }
  };

  if (enabled === null) return null;
  return (
    <div className="mt-3 p-3 rounded-md bg-bg-inset border border-border-subtle">
      <label className="flex items-start gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={enabled}
          onChange={toggle}
          disabled={saving}
          className="mt-0.5"
        />
        <span className="flex-1 text-[11px] text-text-secondary leading-snug">
          <span className="block text-text-primary">
            Help strengthen the privacy network
          </span>
          <span className="block mt-0.5">
            Relay encrypted traffic for other I2P users. You can&rsquo;t see or access
            this traffic. Recommended on Wi-Fi; off by default. Restart the vault
            (lock + unlock) to apply changes.
          </span>
        </span>
      </label>
    </div>
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
