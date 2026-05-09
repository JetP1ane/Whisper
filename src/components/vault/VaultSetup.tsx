import { useMemo, useState } from "react";
import { vaultSetup, vaultRecoverFromSeed } from "../../hooks/useCrypto";
import { NoctisOwl } from "../shared/NoctisLogo";

interface Props {
  onComplete: () => void;
}

type Phase =
  | { kind: "passphrase" }
  | { kind: "show_phrase"; phrase: string }
  | { kind: "recover" };

export function VaultSetup({ onComplete }: Props) {
  const [phase, setPhase] = useState<Phase>({ kind: "passphrase" });

  if (phase.kind === "show_phrase") {
    return (
      <ShowRecoveryPhrase phrase={phase.phrase} onContinue={onComplete} />
    );
  }
  if (phase.kind === "recover") {
    return (
      <RecoverFromSeed
        onRecovered={onComplete}
        onCancel={() => setPhase({ kind: "passphrase" })}
      />
    );
  }
  return (
    <PassphraseStep
      onCreated={(phrase) => setPhase({ kind: "show_phrase", phrase })}
      onChooseRecover={() => setPhase({ kind: "recover" })}
    />
  );
}

// =====================================================================

function PassphraseStep({
  onCreated,
  onChooseRecover,
}: {
  onCreated: (phrase: string) => void;
  onChooseRecover: () => void;
}) {
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const strength = useMemo(() => scoreStrength(pass), [pass]);
  const matches = pass.length > 0 && pass === confirm;

  const submit = async () => {
    if (!matches) {
      setError("Passphrases don't match.");
      return;
    }
    // Strength is shown but not enforced — the user picks their own
    // threat model. The StrengthBar above gives visible feedback so
    // the choice is informed.
    setBusy(true);
    setError(null);
    try {
      const r = await vaultSetup(pass);
      onCreated(r.recovery_phrase);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center bg-bg-base">
      <div className="w-[420px] panel border rounded-xl p-6 animate-slide-up">
        <div className="flex items-center gap-2 text-text-tertiary">
          <NoctisOwl size={14} />
          <span className="text-[10px] font-mono uppercase tracking-wider">
            Step 2 of 3 — vault
          </span>
        </div>
        <h1 className="text-lg text-text-primary mt-1">Set a vault passphrase</h1>
        <p className="text-xs text-text-secondary mt-2 leading-relaxed">
          This passphrase encrypts everything on your device. We can't recover it
          for you. After setup, Touch ID will be required for sensitive operations.
        </p>

        <div className="mt-5 space-y-3">
          <input
            type="password"
            autoFocus
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            placeholder="Passphrase"
            className="input"
          />
          <StrengthBar score={strength} />
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            placeholder="Confirm passphrase"
            className="input"
          />
        </div>

        {error && <div className="mt-3 text-xs text-status-err">{error}</div>}

        <button
          disabled={!matches || busy}
          onClick={submit}
          className="btn-primary w-full mt-5 disabled:opacity-40"
        >
          {busy ? "Generating identity…" : "Create vault"}
        </button>

        <div className="mt-4 text-center">
          <button
            onClick={onChooseRecover}
            className="text-[11px] text-text-tertiary hover:text-text-secondary"
          >
            Already have a recovery phrase? Restore from seed
          </button>
        </div>
      </div>
    </div>
  );
}

// =====================================================================

function ShowRecoveryPhrase({
  phrase,
  onContinue,
}: {
  phrase: string;
  onContinue: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const words = phrase.split(/\s+/);

  return (
    <div className="flex-1 flex items-center justify-center bg-bg-base">
      <div className="w-[520px] panel border rounded-xl p-6 animate-slide-up">
        <div className="flex items-center gap-2 text-text-tertiary">
          <NoctisOwl size={14} />
          <span className="text-[10px] font-mono uppercase tracking-wider">
            Step 3 of 3 — recovery phrase
          </span>
        </div>
        <h1 className="text-lg text-text-primary mt-1">
          Write these 12 words down
        </h1>
        <p className="text-xs text-text-secondary mt-2 leading-relaxed">
          This is the only way to restore your identity if you lose this device.
          Anyone with these words can recover your account. Don't screenshot,
          don't email, don't store online — pen and paper, or a hardware
          password manager.
        </p>
        <p className="text-[11px] text-status-err mt-2 leading-snug">
          Use these only to <em>move</em> Whisper to a new device, not to run
          it on a second device alongside this one. Whisper isn't a
          multi-device app — each install registers separately on the
          network, and contacts will only reach the copy they paired with.
        </p>

        <div className="mt-5 grid grid-cols-3 gap-2 px-2 py-3 rounded-md bg-bg-inset border border-border-subtle">
          {words.map((w, i) => (
            <div key={i} className="flex items-baseline gap-1.5">
              <span className="text-[10px] font-mono text-text-tertiary tabular-nums w-4 text-right">
                {i + 1}
              </span>
              <span className="text-[13px] font-mono text-text-primary">
                {w}
              </span>
            </div>
          ))}
        </div>

        <div className="mt-3 flex items-center gap-2">
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
            {copied ? "Copied" : "Copy to clipboard"}
          </button>
          <span className="text-[10px] text-text-tertiary">
            Paste into your password manager, then clear your clipboard.
          </span>
        </div>

        <label className="mt-5 flex items-start gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            className="mt-0.5"
          />
          <span className="text-[11px] text-text-secondary leading-snug">
            I've written down or stored these 12 words. I understand they
            are the only way to recover my account.
          </span>
        </label>

        <button
          onClick={onContinue}
          disabled={!acknowledged}
          className="btn-primary w-full mt-4 disabled:opacity-40"
        >
          Continue
        </button>
      </div>
    </div>
  );
}

// =====================================================================

function RecoverFromSeed({
  onRecovered,
  onCancel,
}: {
  onRecovered: () => void;
  onCancel: () => void;
}) {
  const [phrase, setPhrase] = useState("");
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const wordCount = phrase.trim().split(/\s+/).filter(Boolean).length;
  const matches = pass.length > 0 && pass === confirm;

  const submit = async () => {
    if (wordCount !== 12) {
      setError(`Recovery phrase must be 12 words (you typed ${wordCount}).`);
      return;
    }
    if (!matches) {
      setError("Passphrases don't match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // No existing vault yet (this is the fresh-install flow), so the
      // M-14 destructive-wipe gate is a no-op — pass `true` so the call
      // succeeds either way.
      await vaultRecoverFromSeed(pass, phrase.trim(), true);
      onRecovered();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center bg-bg-base">
      <div className="w-[480px] panel border rounded-xl p-6 animate-slide-up">
        <div className="flex items-center gap-2 text-text-tertiary">
          <NoctisOwl size={14} />
          <span className="text-[10px] font-mono uppercase tracking-wider">
            Restore from recovery phrase
          </span>
        </div>
        <h1 className="text-lg text-text-primary mt-1">Welcome back</h1>
        <p className="text-xs text-text-secondary mt-2 leading-relaxed">
          Enter your 12-word recovery phrase. Your Whisper ID and identity keys
          will be re-derived; old chat history and contacts won't come back —
          message history is local-only by design.
        </p>

        <div className="mt-5 space-y-3">
          <textarea
            autoFocus
            value={phrase}
            onChange={(e) => setPhrase(e.target.value.toLowerCase())}
            placeholder="word1 word2 word3 …"
            rows={3}
            className="input font-mono resize-none"
          />
          <div className="text-[10px] text-text-tertiary">
            {wordCount} / 12 words
          </div>
          <input
            type="password"
            value={pass}
            onChange={(e) => setPass(e.target.value)}
            placeholder="New vault passphrase"
            className="input"
          />
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && submit()}
            placeholder="Confirm passphrase"
            className="input"
          />
        </div>

        {error && <div className="mt-3 text-xs text-status-err">{error}</div>}

        <div className="mt-5 flex gap-2">
          <button onClick={onCancel} disabled={busy} className="btn-ghost flex-1 text-xs">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={busy || wordCount !== 12 || !matches || pass.length < 8}
            className="btn-primary flex-1 text-xs disabled:opacity-40"
          >
            {busy ? "Restoring…" : "Restore"}
          </button>
        </div>
      </div>
    </div>
  );
}

// =====================================================================

function scoreStrength(p: string): number {
  let s = 0;
  if (p.length >= 12) s++;
  if (p.length >= 20) s++;
  if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
  if (/\d/.test(p)) s++;
  if (/[^A-Za-z0-9]/.test(p)) s++;
  return Math.min(s, 4);
}

function StrengthBar({ score }: { score: number }) {
  const colors = ["bg-bg-raised", "bg-status-err", "bg-status-warn", "bg-accent-500", "bg-status-ok"];
  return (
    <div className="flex gap-1">
      {[0, 1, 2, 3].map((i) => (
        <div
          key={i}
          className={`h-1 flex-1 rounded-full transition-colors ${
            i < score ? colors[score] : "bg-border-subtle"
          }`}
        />
      ))}
    </div>
  );
}
