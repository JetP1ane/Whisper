import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  vaultViewRecoveryPhrase,
  i2pGetSource,
  i2pSetSource,
  i2pTestSource,
  type I2pSource,
} from "../../hooks/useCrypto";

interface SecurityStatus {
  vault_unlocked: boolean;
  hardware_tier: string;
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
          <Card
            label="Transport"
            ok={i2p?.ready ?? false}
            value={i2p?.ready ? "Peer-to-peer" : "—"}
          />
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
        <TransitOptInRow />
        <I2pSourceRow />
      </div>
      <EgressAuditRow />
      <RecoveryPhraseRow />
    </section>
  );
}

interface EgressConnection {
  proto: string;
  local_addr: string;
  remote_addr: string;
  state: string;
  is_loopback: boolean;
  is_expected: boolean;
}

interface EgressAudit {
  connections: EgressConnection[];
  expected_sam_addr: string | null;
  unexpected_count: number;
}

function EgressAuditRow() {
  const [audit, setAudit] = useState<EgressAudit | null>(null);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const a = await invoke<EgressAudit>("egress_audit");
        if (!cancelled) setAudit(a);
      } catch {
        /* lsof unavailable or busy — try next tick */
      }
    };
    tick();
    const t = setInterval(tick, 5_000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  if (!audit) return null;
  const expected = audit.connections.filter((c) => c.is_expected).length;
  const total = audit.connections.length;
  const unexpected = audit.unexpected_count;
  const allClean = unexpected === 0;

  return (
    <div>
      <h3 className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary mb-2">
        Network connections
      </h3>
      <div
        className={
          "p-3 rounded-md border " +
          (allClean
            ? // Healthy state: neutral panel chrome so the small green
              // status dot is what carries the signal, not a green-tinted
              // wash of the whole panel. Reserves the tinted-panel
              // treatment for the unhealthy state where it actually
              // means "look at this".
              "bg-bg-raised border-border-subtle"
            : "bg-status-err/10 border-status-err/40")
        }
      >
        <div className="flex items-start gap-2">
          <span
            className={
              "w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 " +
              (allClean ? "bg-status-ok" : "bg-status-err animate-pulse")
            }
          />
          <div className="flex-1 min-w-0">
            <div className="text-xs text-text-primary">
              {allClean ? (
                <>
                  {expected === 0 ? (
                    <>No active connections from this app.</>
                  ) : (
                    <>
                      {expected} connection{expected === 1 ? "" : "s"} —
                      <span className="text-text-secondary"> all to local I2P bridge</span>
                    </>
                  )}
                </>
              ) : (
                <span className="text-status-err">
                  {unexpected} unexpected outbound connection
                  {unexpected === 1 ? "" : "s"} detected
                </span>
              )}
            </div>
            <div className="text-[10px] text-text-tertiary mt-0.5">
              Audit covers this Whisper process only. The I2P daemon's traffic
              is anonymized and not listed here.
            </div>
            {total > 0 && (
              <button
                onClick={() => setExpanded((e) => !e)}
                className="mt-2 text-[10px] font-mono uppercase tracking-wider text-text-tertiary hover:text-text-secondary"
              >
                {expanded ? "hide details" : "show details"}
              </button>
            )}
            {expanded && (
              <ul className="mt-2 space-y-1">
                {audit.connections.map((c, i) => (
                  <li
                    key={i}
                    className="text-[10px] font-mono text-text-secondary flex items-center gap-2"
                  >
                    <span
                      className={
                        "w-1 h-1 rounded-full shrink-0 " +
                        (c.is_expected
                          ? "bg-status-ok"
                          : c.state === "LISTEN"
                          ? "bg-text-tertiary"
                          : "bg-status-err")
                      }
                    />
                    <span>
                      {c.proto} {c.local_addr} → {c.remote_addr}
                      {c.state ? ` (${c.state})` : ""}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
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

function I2pSourceRow() {
  const [source, setSource] = useState<I2pSource | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  // Draft values while editing — only committed on Save.
  const [host, setHost] = useState("127.0.0.1");
  const [port, setPort] = useState("7656");
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testResult, setTestResult] = useState<
    { ok: true } | { ok: false; msg: string } | null
  >(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    i2pGetSource()
      .then((s) => {
        setSource(s);
        if (s.kind === "external") {
          setHost(s.host);
          setPort(String(s.port));
          setShowAdvanced(true);
        }
      })
      .catch(() => setSource({ kind: "bundled" }));
  }, []);

  if (!source) return null;

  const draft: I2pSource = showAdvanced
    ? { kind: "external", host: host.trim(), port: Number(port) || 0 }
    : { kind: "bundled" };

  const isValid =
    draft.kind === "bundled" ||
    (draft.host.length > 0 && draft.port > 0 && draft.port <= 65535);

  const onTest = async () => {
    if (!isValid || testing) return;
    setTesting(true);
    setTestResult(null);
    try {
      await i2pTestSource(draft);
      setTestResult({ ok: true });
    } catch (e) {
      setTestResult({ ok: false, msg: String(e) });
    } finally {
      setTesting(false);
    }
  };

  const onSave = async () => {
    if (!isValid || saving) return;
    setSaving(true);
    setSaveError(null);
    setSaved(false);
    try {
      await i2pSetSource(draft);
      setSource(draft);
      setSaved(true);
      setTimeout(() => setSaved(false), 4000);
    } catch (e) {
      setSaveError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const currentLabel =
    source.kind === "bundled"
      ? "Bundled router (default)"
      : `External: ${source.host}:${source.port}`;

  return (
    <div className="mt-3 p-3 rounded-md bg-bg-inset border border-border-subtle space-y-3">
      <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
        I2P router
      </div>
      <div className="text-[11px] text-text-secondary leading-snug">
        Current: <span className="text-text-primary">{currentLabel}</span>
      </div>

      <label className="flex items-start gap-3 cursor-pointer">
        <input
          type="checkbox"
          checked={showAdvanced}
          onChange={(e) => {
            setShowAdvanced(e.target.checked);
            setTestResult(null);
            setSaveError(null);
          }}
          className="mt-0.5"
        />
        <span className="flex-1 text-[11px] text-text-secondary leading-snug">
          <span className="block text-text-primary">
            Use my own I2P router instead of the bundled one
          </span>
          <span className="block mt-0.5">
            Whisper will connect to a SAM v3 bridge you provide instead of
            spawning the bundled, integrity-pinned i2pd. Useful if you already
            run i2pd or Java I2P and want Whisper to share its NetDB and
            tunnels.
          </span>
        </span>
      </label>

      {showAdvanced && (
        <>
          <div className="text-[11px] text-status-err leading-snug">
            You're substituting your own router for ours. Whisper's bundled-
            binary SHA-256 pin and Hardened-Runtime-signed dylibs only apply to
            the included i2pd. For external routers, you own the trust
            assumptions on the binary, config, peer selection, and any network
            exposure of the SAM endpoint.
          </div>

          <div className="grid grid-cols-[1fr_120px] gap-2">
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-text-tertiary mb-1">
                Host
              </label>
              <input
                type="text"
                value={host}
                onChange={(e) => {
                  setHost(e.target.value);
                  setTestResult(null);
                  setSaveError(null);
                }}
                placeholder="127.0.0.1"
                className="input text-xs"
              />
            </div>
            <div>
              <label className="block text-[10px] font-mono uppercase tracking-wider text-text-tertiary mb-1">
                Port
              </label>
              <input
                type="text"
                inputMode="numeric"
                value={port}
                onChange={(e) => {
                  setPort(e.target.value);
                  setTestResult(null);
                  setSaveError(null);
                }}
                placeholder="7656"
                className="input text-xs font-mono"
              />
            </div>
          </div>
          <p className="text-[10px] text-text-tertiary leading-snug">
            i2pd's SAM v3 default is <span className="font-mono">7656</span>. If
            your router exposes SAM only on loopback (recommended), use
            <span className="font-mono"> 127.0.0.1</span>. Whisper accepts any
            reachable host, but exposing SAM to the network broadens your
            router's attack surface — confirm that's actually what you want.
          </p>
        </>
      )}

      <div className="flex gap-2 items-center">
        <button
          onClick={onTest}
          disabled={!isValid || testing}
          className="btn-ghost text-xs disabled:opacity-40"
        >
          {testing ? "Testing…" : "Test connection"}
        </button>
        <button
          onClick={onSave}
          disabled={!isValid || saving}
          className="btn-primary text-xs disabled:opacity-40"
        >
          {saving ? "Saving…" : "Save"}
        </button>
        {testResult?.ok === true && (
          <span className="text-[11px] text-status-ok">
            ✓ Test succeeded
          </span>
        )}
        {testResult?.ok === false && (
          <span className="text-[11px] text-status-err truncate">
            ✗ {testResult.msg}
          </span>
        )}
      </div>

      {saveError && (
        <div className="text-[11px] text-status-err leading-snug">
          {saveError}
        </div>
      )}
      {saved && (
        <div className="text-[11px] text-status-ok leading-snug">
          Saved. Lock and unlock the vault (or restart the app) to apply.
        </div>
      )}
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
      <p className="text-xs text-text-secondary leading-relaxed mb-2">
        12 words that can rebuild your Whisper ID on a new device if you ever
        lose this Mac. Anyone with these words can take over your account —
        store them offline.
      </p>
      <p className="text-[11px] text-status-err leading-snug mb-3">
        Use these only to <em>move</em> to a new device, not to run Whisper on
        two at once. Whisper isn't a multi-device app — each install registers
        separately on the network, so contacts you've already added will only
        reach the copy they paired with.
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
      <p className="text-[11px] text-status-err leading-snug">
        Reminder: don't enter these on another device while this one is still
        in use. Whisper isn't a multi-device app.
      </p>
      <div className="flex gap-2">
        <button
          onClick={async () => {
            const { writeText } = await import(
              "@tauri-apps/plugin-clipboard-manager"
            );
            await writeText(phrase);
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
      return "Hardware-bound + Touch ID";
    case "secure_enclave":
      return "Hardware-bound";
    case "software_only":
      return "Software";
    default:
      return "—";
  }
}
