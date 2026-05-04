import { useState } from "react";
import { vaultUnlock, vaultRecoverFromSeed } from "../../hooks/useCrypto";
import { NoctisOwl } from "../shared/NoctisLogo";

interface Props {
  onUnlock: () => void;
}

type Mode = "unlock" | "recover";

export function VaultLock({ onUnlock }: Props) {
  const [mode, setMode] = useState<Mode>("unlock");
  if (mode === "recover") {
    return <RecoverPanel onRecovered={onUnlock} onCancel={() => setMode("unlock")} />;
  }
  return <UnlockPanel onUnlock={onUnlock} onChooseRecover={() => setMode("recover")} />;
}

function UnlockPanel({
  onUnlock,
  onChooseRecover,
}: {
  onUnlock: () => void;
  onChooseRecover: () => void;
}) {
  const [pass, setPass] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await vaultUnlock(pass);
      onUnlock();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex-1 flex items-center justify-center bg-bg-base">
      <div className="w-[360px] panel border rounded-xl p-6 animate-slide-up">
        <div className="flex items-center gap-2 text-text-tertiary">
          <NoctisOwl size={14} />
          <span className="text-[10px] font-mono uppercase tracking-wider">
            Vault
          </span>
        </div>
        <h1 className="text-lg text-text-primary mt-1 mb-4">Welcome back</h1>

        <input
          type="password"
          autoFocus
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          placeholder="Vault passphrase"
          className="input"
        />
        {error && (
          <div className="mt-2 text-xs text-status-err">{error}</div>
        )}

        <button
          disabled={!pass || busy}
          onClick={submit}
          className="btn-primary w-full mt-4 disabled:opacity-40"
        >
          {busy ? "Unlocking…" : "Unlock"}
        </button>

        <div className="mt-4 text-center">
          <button
            onClick={onChooseRecover}
            className="text-[11px] text-text-tertiary hover:text-text-secondary"
          >
            Forgot passphrase? Restore from recovery phrase
          </button>
        </div>

        <div className="mt-4 text-[11px] text-text-tertiary text-center">
          Your data never leaves this device unencrypted.
        </div>
      </div>
    </div>
  );
}

function RecoverPanel({
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
  const [confirmingWipe, setConfirmingWipe] = useState(false);

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
    if (pass.length < 8) {
      setError("Passphrase too short.");
      return;
    }
    if (!confirmingWipe) {
      setConfirmingWipe(true);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await vaultRecoverFromSeed(pass, phrase.trim());
      onRecovered();
    } catch (e) {
      setError(String(e));
      setConfirmingWipe(false);
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
        <h1 className="text-lg text-text-primary mt-1">Restore your identity</h1>
        <p className="text-xs text-text-secondary mt-2 leading-relaxed">
          Enter your 12-word recovery phrase. This will <span className="text-status-err">wipe the existing vault on this device</span> and rebuild your identity from the phrase. Local message history is lost; your Whisper ID and contacts on the relay come back.
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
            placeholder="Confirm passphrase"
            className="input"
          />
        </div>

        {error && <div className="mt-3 text-xs text-status-err">{error}</div>}

        {confirmingWipe && (
          <div className="mt-3 text-xs text-status-err font-medium">
            This will erase the existing vault on this device. Click Restore again to confirm.
          </div>
        )}

        <div className="mt-5 flex gap-2">
          <button onClick={onCancel} disabled={busy} className="btn-ghost flex-1 text-xs">
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={busy || wordCount !== 12 || !matches || pass.length < 8}
            className={`btn flex-1 text-xs disabled:opacity-40 ${
              confirmingWipe
                ? "bg-status-err text-white border border-status-err hover:bg-status-err/90"
                : "btn-primary"
            }`}
          >
            {busy ? "Restoring…" : confirmingWipe ? "Yes, wipe and restore" : "Restore"}
          </button>
        </div>
      </div>
    </div>
  );
}
