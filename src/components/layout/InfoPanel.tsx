import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useConversationStore, conversationLabel } from "../../stores/conversationStore";

interface SafetyNumbers {
  digits: number[];
  formatted: string;
  hex_fingerprint: string;
}

interface ConversationSecurity {
  conversation_id: string;
  peer_alias: string | null;
  peer_id_hex: string | null;
  aead: string;
  kex_classical: string;
  kex_pq: string | null;
  kdf: string;
  identity_sig: string;
  messages_sent: number;
  messages_received: number;
  ratchet_send_chain_n: number;
  ratchet_recv_chain_n: number;
  ratchet_prev_chain_len: number;
  skipped_keys_cached: number;
  session_established: boolean;
  is_verified: boolean;
  peer_has_verified_us: boolean;
  is_sealed: boolean;
  disappear_timer_secs: number | null;
  hardware_tier: string;
  safety_numbers: SafetyNumbers;
  peer_i2p_destination: string | null;
  i2p_tunnel_warm: boolean;
}

export function InfoPanel() {
  const selectedId = useConversationStore((s) => s.selectedId);
  const conversations = useConversationStore((s) => s.conversations);
  const messages = useConversationStore((s) => s.messages);
  const [security, setSecurity] = useState<ConversationSecurity | null>(null);
  const [showSafetyNumber, setShowSafetyNumber] = useState(false);
  const [showDeviceProtections, setShowDeviceProtections] = useState(false);

  const conv = conversations.find((c) => c.id === selectedId);

  useEffect(() => {
    if (!selectedId) {
      setSecurity(null);
      return;
    }
    invoke<ConversationSecurity>("conversation_security_summary", {
      conversationId: selectedId,
    })
      .then(setSecurity)
      .catch(() => setSecurity(null));
  }, [selectedId, messages.length, conv?.contact_id]);

  if (!conv) {
    return (
      <aside className="w-[300px] flex-shrink-0 flex items-center justify-center bg-bg-panel border-l border-border-subtle">
        <span className="text-xs text-text-tertiary">No conversation selected</span>
      </aside>
    );
  }

  const label = conversationLabel(conv);
  const isRoom = conv.kind === "room";

  return (
    <aside className="w-[300px] flex-shrink-0 flex flex-col bg-bg-panel border-l border-border-subtle overflow-y-auto">
      {/* Header — alias + truncated identity-key fingerprint. */}
      <div className="px-4 pt-4 pb-3 border-b border-border-subtle">
        <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          {isRoom ? "Room" : "Peer"}
        </div>
        <div className="mt-1 font-mono text-base text-text-primary truncate">{label}</div>
        {security?.peer_id_hex && (
          <div className="mt-1 font-mono text-[10px] text-text-tertiary leading-relaxed break-all">
            {security.peer_id_hex.slice(0, 16)}…{security.peer_id_hex.slice(-16)}
          </div>
        )}
      </div>

      {/* Transport: peer-to-peer, no central server. The architecturally
          distinguishing feature of this app — surface it prominently. */}
      {!isRoom && (
        <Section label="Transport">
          <CipherRow label="Network" value="I2P · peer-to-peer" ok />
          <CipherRow label="Path" value="4 hops · garlic-encrypted" ok />
        </Section>
      )}

      {/* Encryption — algorithms in use for this session. Compact one-line
          rows. The post-quantum row gets the prominent green pill since
          that's the most distinctive guarantee. */}
      <Section label="Encryption">
        <CipherRow label="AEAD" value={security?.aead ?? "—"} ok />
        <CipherRow label="DH" value={security?.kex_classical ?? "—"} ok />
        <CipherRow
          label="DH (post-quantum)"
          value={security?.kex_pq ?? "Classical only"}
          ok={!!security?.kex_pq}
        />
        <CipherRow label="KDF" value={security?.kdf ?? "—"} ok />
        <CipherRow label="Identity" value={security?.identity_sig ?? "—"} ok />
        {security?.kex_pq && (
          <div className="mt-2 px-2 py-1.5 rounded-md border border-accent-500/20 bg-accent-500/5 flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase tracking-wider text-accent-400">
              Quantum protected
            </span>
            <span className="text-[11px] font-mono text-accent-300">ML-KEM-1024</span>
          </div>
        )}
      </Section>

      {/* Hardware integrity — the protections we apply at the device
          + binary level. Expanded list because there's a real story
          to tell (SE anchoring, Hardened Runtime, library validation,
          i2pd binary pin, sandbox entitlements). */}
      <Section label="Hardware integrity">
        <Row
          label="Key binding"
          value={
            <span className="text-[11px] font-mono text-text-primary">
              {prettyTier(security?.hardware_tier)}
            </span>
          }
        />
        <p className="mt-1.5 text-[10px] text-text-tertiary leading-snug">
          {tierExplanation(security?.hardware_tier)}
        </p>
        <button
          onClick={() => setShowDeviceProtections((v) => !v)}
          className="mt-2 w-full text-left text-[10px] font-mono uppercase tracking-wider text-text-tertiary hover:text-text-secondary flex items-center justify-between"
        >
          <span>Device protections</span>
          <span className="text-text-tertiary">
            {showDeviceProtections ? "▾" : "▸"}
          </span>
        </button>
        {showDeviceProtections && (
          <ul className="mt-2 space-y-1 text-[10px] text-text-secondary leading-snug">
            <li className="flex gap-1.5">
              <span className="text-status-ok">✓</span>
              <span>Vault DEK + per-conversation TEE key derived from a hardware-bound seed in this Mac's Keychain (<span className="font-mono">kSecAttrAccessibleWhenUnlockedThisDeviceOnly</span>, non-syncable). The on-disk SQLCipher database can't be opened on another machine.</span>
            </li>
            <li className="flex gap-1.5">
              <span className="text-status-ok">✓</span>
              <span>Recovery phrase reveal requires re-entering your passphrase, then runs a fresh Argon2id derivation against the stored salt before unsealing.</span>
            </li>
            <li className="flex gap-1.5">
              <span className="text-status-ok">✓</span>
              <span>Hardened Runtime + library validation: macOS verifies every dylib's signature before load and blocks <span className="font-mono">DYLD_INSERT_LIBRARIES</span> injection. Verified empirically — Frida and lldb attach are denied by the OS.</span>
            </li>
            <li className="flex gap-1.5">
              <span className="text-status-ok">✓</span>
              <span>Bundled <span className="font-mono">i2pd</span> binary, dylibs, and reseed certs (27 files total) are SHA-256-pinned at build time and re-verified before every launch — any tampered file refuses to start.</span>
            </li>
            <li className="flex gap-1.5">
              <span className="text-status-ok">✓</span>
              <span>App sandbox active. JIT, debugger attach, and <span className="font-mono">DYLD_*</span> env vars all denied at the entitlement level.</span>
            </li>
            <li className="flex gap-1.5">
              <span className="text-status-ok">✓</span>
              <span>Webview CSP locked to <span className="font-mono">self</span> + IPC; no outbound HTTP from the UI is possible.</span>
            </li>
            <li className="flex gap-1.5">
              <span className="text-status-ok">✓</span>
              <span>Live egress audit in Settings → Security: every TCP/UDP socket from this app's PID and from the bundled i2pd subprocess is enumerated, with public-internet endpoints flagged.</span>
            </li>
          </ul>
        )}
      </Section>

      {/* Verification — the user-facing MITM defence. With the relay
          gone, the central-server substitution attack is gone too,
          but the *channel that delivered the whisper:// link* can
          still be tampered with. Safety-number comparison out-of-band
          remains the canonical answer. */}
      {!isRoom && security?.safety_numbers.formatted && (
        <Section label="Verification">
          <Row
            label="Status"
            value={
              security.is_verified ? (
                <Pill tone="ok">Verified</Pill>
              ) : (
                <Pill tone="off">Unverified</Pill>
              )
            }
          />
          <p className="mt-1.5 text-[10px] text-text-tertiary leading-snug">
            Whisper IDs are exchanged via{" "}
            <span className="font-mono">whisper://</span> links you share
            yourselves. If an attacker tampered with the channel that
            carried the link, they could have swapped it for their own.
            Compare these digits with your peer on a separate trusted
            channel (in person, a phone call you trust). Matching digits
            mean no one is in the middle.
          </p>
          {!showSafetyNumber ? (
            <button
              onClick={() => setShowSafetyNumber(true)}
              className="mt-2 w-full text-[11px] font-mono uppercase tracking-wider text-accent-400 hover:text-accent-300 px-2 py-1.5 rounded-md border border-accent-500/20 bg-accent-500/5 hover:bg-accent-500/10"
            >
              Show safety number
            </button>
          ) : (
            <div className="mt-2 space-y-2">
              <div className="px-2 py-2 rounded-md bg-bg-inset border border-border-subtle">
                <div className="font-mono text-[11px] text-text-primary leading-relaxed tracking-wider whitespace-pre-wrap">
                  {security.safety_numbers.formatted}
                </div>
              </div>
              <VerifyToggle
                contactId={conv.contact_id}
                isVerified={security.is_verified}
                onChanged={() => {
                  // Re-fetch the security summary so the pill updates.
                  if (selectedId) {
                    invoke<ConversationSecurity>(
                      "conversation_security_summary",
                      { conversationId: selectedId },
                    )
                      .then(setSecurity)
                      .catch(() => {});
                  }
                }}
              />
            </div>
          )}
        </Section>
      )}

    </aside>
  );
}

function VerifyToggle({
  contactId,
  isVerified,
  onChanged,
}: {
  contactId: string | null;
  isVerified: boolean;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  if (!contactId) return null;
  const flip = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await invoke("contact_verify", {
        id: contactId,
        verified: !isVerified,
      });
      onChanged();
    } catch {
      /* surface as unchanged state */
    } finally {
      setBusy(false);
    }
  };
  if (isVerified) {
    return (
      <button
        onClick={flip}
        disabled={busy}
        className="w-full text-[11px] font-mono uppercase tracking-wider text-text-tertiary hover:text-text-secondary px-2 py-1.5 rounded-md border border-border-subtle bg-bg-inset hover:bg-bg-active disabled:opacity-40"
        title="Reset the verification flag if the safety number ever changes (e.g. peer reinstalled)."
      >
        {busy ? "Resetting…" : "Reset verification"}
      </button>
    );
  }
  return (
    <button
      onClick={flip}
      disabled={busy}
      className="w-full text-[11px] font-mono uppercase tracking-wider text-status-ok hover:opacity-80 px-2 py-1.5 rounded-md border border-status-ok/30 bg-status-ok/10 hover:bg-status-ok/20 disabled:opacity-40"
    >
      {busy ? "Marking…" : "Mark as verified"}
    </button>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="px-4 py-3 border-b border-border-subtle">
      <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary mb-2">
        {label}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="text-xs text-text-secondary">{label}</span>
      {value}
    </div>
  );
}

function CipherRow({ label, value, ok }: { label: string; value: string; ok?: boolean }) {
  return (
    <div className="flex items-center justify-between py-1">
      <span className="text-xs text-text-secondary">{label}</span>
      <div className="flex items-center gap-1.5">
        <span
          className={`w-1.5 h-1.5 rounded-full ${ok ? "bg-status-ok" : "bg-text-tertiary"}`}
        />
        <span className="text-[11px] font-mono text-text-primary">{value}</span>
      </div>
    </div>
  );
}


function Pill({
  tone,
  children,
}: {
  tone: "ok" | "warn" | "err" | "off";
  children: React.ReactNode;
}) {
  const cls =
    tone === "ok"
      ? "bg-status-ok/10 text-status-ok border-status-ok/30"
      : tone === "warn"
      ? "bg-status-warn/10 text-status-warn border-status-warn/30"
      : tone === "err"
      ? "bg-status-err/10 text-status-err border-status-err/30"
      : "bg-bg-inset text-text-tertiary border-border-default";
  return (
    <span className={`px-1.5 py-0.5 rounded border text-[10px] font-mono uppercase tracking-wider ${cls}`}>
      {children}
    </span>
  );
}

function prettyTier(t: string | undefined): string {
  switch (t) {
    case "secure_enclave_biometric":
      // Reserved tier for when sealed-conversation keys are gated by Touch ID.
      // Currently unused — the always-on DB seed isn't biometric-gated, so
      // we don't claim it. Kept for forward-compat with the Rust enum.
      return "Hardware-bound + Touch ID";
    case "secure_enclave":
      return "Hardware-bound";
    case "software_only":
      return "Software";
    default:
      return "—";
  }
}

function tierExplanation(t: string | undefined): string {
  switch (t) {
    case "secure_enclave_biometric":
      return "Your seeds are stored in this Mac's Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly + Synchronizable=false, gated by a Touch ID prompt for sensitive operations. While the vault is unlocked, derived seeds live in this app's memory; locking the vault clears them.";
    case "secure_enclave":
      return "Your seeds are stored in this Mac's Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly + Synchronizable=false. The Keychain blob never leaves this device — copying the database file to another machine cannot decrypt your vault. While the vault is unlocked, derived seeds live in this app's memory; locking the vault clears them.";
    case "software_only":
      return "Your seeds are stored in a per-profile config file, encrypted at rest with your vault passphrase. (Not running on macOS — no Keychain available.)";
    default:
      return "";
  }
}
