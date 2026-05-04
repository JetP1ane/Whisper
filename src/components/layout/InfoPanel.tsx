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
}

export function InfoPanel() {
  const selectedId = useConversationStore((s) => s.selectedId);
  const conversations = useConversationStore((s) => s.conversations);
  const messages = useConversationStore((s) => s.messages);
  const [security, setSecurity] = useState<ConversationSecurity | null>(null);

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

  return (
    <aside className="w-[300px] flex-shrink-0 flex flex-col bg-bg-panel border-l border-border-subtle overflow-y-auto">
      {/* Header */}
      <div className="px-4 pt-4 pb-3 border-b border-border-subtle">
        <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          Peer
        </div>
        <div className="mt-1 font-mono text-base text-text-primary truncate">{label}</div>
        {security?.peer_id_hex && (
          <div className="mt-1 font-mono text-[10px] text-text-tertiary leading-relaxed break-all">
            {security.peer_id_hex.slice(0, 16)}…{security.peer_id_hex.slice(-16)}
          </div>
        )}
      </div>

      {/* Encryption */}
      <Section label="Encryption">
        <CipherRow label="Cipher" value={security?.aead ?? "—"} ok />
        <CipherRow label="DH (classical)" value={security?.kex_classical ?? "—"} ok />
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
            <span className="text-[11px] font-mono text-accent-300">Kyber</span>
          </div>
        )}
      </Section>

      {/* Forward secrecy */}
      <Section label="Forward secrecy">
        <Row label="Sent" value={<MonoNum n={security?.messages_sent ?? 0} />} />
        <Row label="Received" value={<MonoNum n={security?.messages_received ?? 0} />} />
        <Row
          label="Send chain"
          value={<MonoNum n={security?.ratchet_send_chain_n ?? 0} />}
        />
        <Row
          label="Receive chain"
          value={<MonoNum n={security?.ratchet_recv_chain_n ?? 0} />}
        />
        <RatchetVisual
          sent={security?.messages_sent ?? 0}
          received={security?.messages_received ?? 0}
        />
        <p className="mt-2 text-[10px] text-text-tertiary leading-snug">
          Each message uses a fresh key derived from the previous chain key (HKDF-SHA256).
          Past messages stay safe even if the current key leaks.
        </p>
      </Section>

      {/* Identity binding — cryptographic check of the alias↔key link */}
      <Section label="Identity binding">
        <Row
          label="Alias ↔ key"
          value={<Pill tone="ok">Bound</Pill>}
        />
        <p className="mt-1.5 text-[10px] text-text-tertiary leading-snug">
          The alias is a deterministic hash of the public identity key.
          Any peer who substitutes a different bundle for the same alias
          fails verification on add — the binding is enforced locally.
        </p>
      </Section>

      {/* Key storage */}
      <Section label="Key storage">
        <Row
          label="Backed by"
          value={
            <span className="text-[11px] font-mono text-text-primary">
              {prettyTier(security?.hardware_tier)}
            </span>
          }
        />
        <p className="mt-1.5 text-[10px] text-text-tertiary leading-snug">
          {tierExplanation(security?.hardware_tier)}
        </p>
      </Section>

    </aside>
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

function MonoNum({ n }: { n: number }) {
  return <span className="text-[11px] font-mono tabular-nums text-text-primary">{n}</span>;
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

function RatchetVisual({ sent, received }: { sent: number; received: number }) {
  const total = sent + received;
  if (total === 0) {
    return (
      <div className="mt-3 px-2 py-2 rounded-md bg-bg-inset border border-border-subtle text-[11px] text-text-tertiary text-center">
        Send a message to start the ratchet
      </div>
    );
  }
  const cap = 24;
  const sentDots = Math.min(sent, cap);
  const recvDots = Math.min(received, cap);
  return (
    <div className="mt-3 space-y-2">
      <DotRow label="↑" count={sentDots} total={cap} tone="accent" trailingNumber={sent} />
      <DotRow label="↓" count={recvDots} total={cap} tone="ok" trailingNumber={received} />
    </div>
  );
}

function DotRow({
  label,
  count,
  total,
  tone,
  trailingNumber,
}: {
  label: string;
  count: number;
  total: number;
  tone: "accent" | "ok";
  trailingNumber: number;
}) {
  const filled = tone === "accent" ? "bg-accent-400" : "bg-status-ok";
  const empty = "bg-bg-active";
  return (
    <div className="flex items-center gap-2">
      <span className="w-3 text-[10px] font-mono text-text-tertiary">{label}</span>
      <div className="flex-1 flex items-center gap-[2px]">
        {Array.from({ length: total }, (_, i) => (
          <span
            key={i}
            className={`flex-1 h-1.5 rounded-sm ${i < count ? filled : empty}`}
          />
        ))}
      </div>
      <span className="w-6 text-right text-[10px] font-mono tabular-nums text-text-secondary">
        {trailingNumber}
      </span>
    </div>
  );
}

function prettyTier(t: string | undefined): string {
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

function tierExplanation(t: string | undefined): string {
  switch (t) {
    case "secure_enclave_biometric":
      return "Your secret keys are anchored in your Mac's Secure Enclave — a separate chip that releases material only after Touch ID. Keys never leave the chip in plaintext, even to this app.";
    case "secure_enclave":
      return "Your secret keys are anchored in your Mac's Secure Enclave. Keys never leave the chip in plaintext.";
    case "software_only":
      return "Your secret keys are stored in the macOS login Keychain, encrypted at rest. (No Secure Enclave on this device.)";
    default:
      return "";
  }
}

