import { useEffect, useState } from "react";
import { getIdentity, IdentitySummary } from "../../hooks/useCrypto";
import { NoctisOwl } from "../shared/NoctisLogo";

interface Props {
  onContinue: () => void;
  /** Set after vault setup so we can display the freshly minted alias. */
  showAlias?: boolean;
}

export function OnboardingFlow({ onContinue, showAlias = false }: Props) {
  const [identity, setIdentity] = useState<IdentitySummary | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (showAlias) {
      getIdentity().then(setIdentity).catch(() => {});
    }
  }, [showAlias]);

  if (showAlias) {
    return (
      <div className="flex-1 flex items-center justify-center bg-bg-base">
        <div className="w-[480px] text-center animate-fade-in">
          <div className="mx-auto mb-6 text-accent-500 flex justify-center">
            <NoctisOwl size={80} />
          </div>
          <h1 className="text-2xl text-text-primary tracking-tight">Your Whisper ID</h1>
          <p className="text-xs text-text-secondary mt-3 max-w-[360px] mx-auto leading-relaxed">
            Share this with people you want to message. It's derived from your public key — no
            phone number, no email, no account.
          </p>
          <div className="my-6 px-4 py-3 mx-auto w-fit rounded-lg bg-bg-panel border border-border-default">
            <span className="font-mono text-lg text-accent-300 tracking-wide">
              {identity?.alias ?? "—"}
            </span>
          </div>
          {identity && (
            <div className="text-[10px] font-mono text-text-tertiary leading-relaxed break-all max-w-[400px] mx-auto">
              {identity.safety_number_hex_fingerprint}
            </div>
          )}
          <div className="mt-8 flex justify-center gap-2">
            <button
              onClick={async () => {
                if (identity) {
                  await navigator.clipboard.writeText(identity.alias);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }
              }}
              className="btn-secondary text-xs"
            >
              {copied ? "Copied" : "Copy ID"}
            </button>
            <button onClick={onContinue} className="btn-primary text-xs">
              Continue
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 flex items-center justify-center bg-bg-base">
      <div className="w-[440px] text-center animate-fade-in">
        <div className="mx-auto mb-6 text-accent-500 flex justify-center">
          <NoctisOwl size={96} />
        </div>
        <h1 className="text-3xl text-text-primary tracking-tight">Whisper</h1>
        <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary mt-1">
          by Noctis Privacy
        </div>
        <p className="text-xs text-text-secondary mt-4 max-w-[320px] mx-auto leading-relaxed">
          Private, post-quantum messenger. No phone numbers, no email, no accounts. Your identity
          is a cryptographic key pair stored locally.
        </p>
        <button onClick={onContinue} className="btn-primary mt-6 px-5">
          Create your secure identity
        </button>
        <div className="mt-4 text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          Step 1 of 3
        </div>
      </div>
    </div>
  );
}
