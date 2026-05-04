interface Props {
  alias: string;
  safetyNumbers: string;        // 12 groups of 5 digits, space-separated
  hexFingerprint: string;       // grouped 8-char hex
  verified: boolean;
  onConfirmVerified: () => void;
}

export function VerifyContact({
  alias,
  safetyNumbers,
  hexFingerprint,
  verified,
  onConfirmVerified,
}: Props) {
  const groups = safetyNumbers.split(" ");
  return (
    <div className="p-4 space-y-4">
      <div>
        <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          Verifying
        </div>
        <div className="text-sm text-text-primary">{alias}</div>
      </div>

      <div>
        <div className="text-xs text-text-secondary mb-2">Safety numbers</div>
        <div className="grid grid-cols-3 gap-x-4 gap-y-2 font-mono">
          {groups.map((g, i) => (
            <span key={i} className="text-text-primary tabular-nums text-[13px]">
              {g}
            </span>
          ))}
        </div>
      </div>

      <div>
        <div className="text-xs text-text-secondary mb-1">Identity key (hex)</div>
        <div className="font-mono text-[11px] text-text-secondary leading-relaxed break-all">
          {hexFingerprint}
        </div>
      </div>

      <div className="pt-2 border-t border-border-subtle">
        <p className="text-xs text-text-secondary mb-3">
          Compare these numbers with {alias} over a trusted channel before marking verified.
        </p>
        <button
          onClick={onConfirmVerified}
          disabled={verified}
          className="btn-primary w-full disabled:opacity-50"
        >
          {verified ? "Verified" : "Mark as verified"}
        </button>
      </div>
    </div>
  );
}
