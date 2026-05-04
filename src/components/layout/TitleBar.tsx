import { useEffect, useState } from "react";
import { useAppStore } from "../../stores/appStore";
import { useTheme } from "../../hooks/useTheme";
import { NoctisOwl } from "../shared/NoctisLogo";

interface TitleBarProps {
  onOpenSettings?: () => void;
  onLock?: () => void;
}

export function TitleBar({ onOpenSettings, onLock }: TitleBarProps = {}) {
  const vault = useAppStore((s) => s.vault);
  const refreshRelay = useAppStore((s) => s.refreshRelay);
  const relay = useAppStore((s) => s.relay);
  const [tier, setTier] = useState<string>("");
  const [tierRaw, setTierRaw] = useState<string>("");
  const { theme, toggle } = useTheme();

  useEffect(() => {
    refreshRelay();
    const t = setInterval(refreshRelay, 10_000);
    return () => clearInterval(t);
  }, [refreshRelay]);

  useEffect(() => {
    if (vault?.hardware_tier) {
      setTier(formatTier(vault.hardware_tier));
      setTierRaw(vault.hardware_tier);
    }
  }, [vault]);

  return (
    <div
      data-tauri-drag-region
      className="titlebar flex items-center justify-between px-3 bg-bg-base border-b border-border-subtle"
    >
      {/* macOS traffic-light spacer (titleBarStyle: Overlay floats them here) */}
      <div data-tauri-drag-region className="w-[72px]" />

      <div
        data-tauri-drag-region
        className="flex items-center gap-2 text-[11px] text-text-tertiary"
      >
        <NoctisOwl size={14} className="text-text-secondary" />
        <span data-tauri-drag-region className="font-mono tracking-wider uppercase">
          whisper
        </span>
      </div>

      <div className="flex items-center gap-2">
        <SecurityShield
          tier={tier}
          tierRaw={tierRaw}
          unlocked={!!vault?.unlocked}
          relayConnected={!!relay?.connected}
        />
        <button
          onClick={toggle}
          className="px-2 py-1 rounded-md hover:bg-bg-hover transition-colors text-text-tertiary"
          title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
        >
          {theme === "dark" ? <SunIcon /> : <MoonIcon />}
        </button>
        {onOpenSettings && (
          <button
            onClick={onOpenSettings}
            className="px-2 py-1 rounded-md hover:bg-bg-hover transition-colors text-text-tertiary"
            title="Settings"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
            </svg>
          </button>
        )}
        {onLock && (
          <button
            onClick={onLock}
            className="px-2 py-1 rounded-md hover:bg-bg-hover transition-colors text-text-tertiary"
            title="Lock vault (⌘L)"
          >
            <LockIcon />
          </button>
        )}
      </div>
    </div>
  );
}

function SecurityShield({
  tier,
  tierRaw,
  unlocked,
  relayConnected,
}: {
  tier: string;
  tierRaw: string;
  unlocked: boolean;
  relayConnected: boolean;
}) {
  const [open, setOpen] = useState(false);
  // Wrap a click-outside handler around the popover.
  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target.closest("[data-security-shield]")) setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [open]);

  const protectedByEnclave =
    tierRaw === "secure_enclave" || tierRaw === "secure_enclave_biometric";
  const biometric = tierRaw === "secure_enclave_biometric";
  const healthy = unlocked && relayConnected && protectedByEnclave;
  const shieldColor = healthy
    ? "text-status-ok"
    : protectedByEnclave
    ? "text-status-warn"
    : "text-text-tertiary";

  return (
    <div data-security-shield className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className={`px-2 py-1 rounded-md hover:bg-bg-hover transition-colors ${shieldColor}`}
        title={
          protectedByEnclave
            ? `Keys protected by ${tier}. Click for details.`
            : "Keys are stored in software. Click for details."
        }
      >
        <ShieldIcon filled={protectedByEnclave} />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 w-[300px] rounded-lg border border-border-default bg-bg-panel shadow-xl p-3 z-50 animate-fade-in">
          <div className="flex items-center gap-2 mb-2">
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                healthy ? "bg-status-ok" : "bg-status-warn"
              }`}
            />
            <span className="text-xs text-text-primary font-medium">
              {protectedByEnclave
                ? biometric
                  ? "Hardware + biometric"
                  : "Hardware-backed"
                : "Software-only"}
            </span>
            <span className="ml-auto text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
              {tier || "—"}
            </span>
          </div>
          <p className="text-[11px] text-text-secondary leading-relaxed">
            {protectedByEnclave
              ? `Your secret keys are anchored in this Mac's Secure Enclave — a separate chip that never releases key material in plaintext, even to this app.${
                  biometric
                    ? " Touch ID is required to release sensitive operations."
                    : ""
                }`
              : "This device has no Secure Enclave. Your keys are stored in the macOS login Keychain, encrypted at rest with your vault passphrase."}
          </p>
          <div className="mt-3 text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
            What this protects
          </div>
          <ul className="mt-1 space-y-0.5 text-[11px] text-text-secondary">
            <li>• Your long-term identity keys (Ed25519 + X25519 + ML-KEM)</li>
            <li>• Vault encryption key (DEK) sealing the SQLCipher database</li>
            <li>• Configuration manifest signer (relay-tampering detector)</li>
            <li>• Per-conversation TEE keys protecting message bodies at rest</li>
            <li>• Room sender-key chain seeds</li>
          </ul>
        </div>
      )}
    </div>
  );
}

function ShieldIcon({ filled }: { filled: boolean }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      {filled && (
        <path
          d="m9 12 2 2 4-4"
          stroke="white"
          fill="none"
          strokeWidth="2.2"
        />
      )}
    </svg>
  );
}

function formatTier(t: string): string {
  switch (t) {
    case "secure_enclave_biometric":
      return "SE+TouchID";
    case "secure_enclave":
      return "SE";
    case "software_only":
      return "Software";
    default:
      return "—";
  }
}

function SunIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m6.34 17.66-1.41 1.41" />
      <path d="m19.07 4.93-1.41 1.41" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

function LockIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}
