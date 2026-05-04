import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Prefs {
  enabled: boolean;
  show_preview: boolean;
  sound: boolean;
}

const DEFAULT_PREFS: Prefs = {
  enabled: true,
  show_preview: true,
  sound: true,
};

export function NotificationsConfig() {
  const [prefs, setPrefs] = useState<Prefs>(DEFAULT_PREFS);
  const [loaded, setLoaded] = useState(false);
  const [savingNote, setSavingNote] = useState<string | null>(null);

  useEffect(() => {
    invoke<Prefs>("notifications_get")
      .then((p) => {
        setPrefs(p);
        setLoaded(true);
      })
      .catch(() => setLoaded(true));
  }, []);

  const update = async (next: Prefs) => {
    setPrefs(next);
    try {
      await invoke("notifications_set", { prefs: next });
    } catch (e) {
      setSavingNote(String(e));
    }
  };

  const test = async () => {
    setSavingNote(null);
    try {
      await invoke("notifications_test");
      setSavingNote("Test notification fired.");
    } catch (e) {
      setSavingNote(String(e));
    }
  };

  if (!loaded) {
    return (
      <section className="space-y-2">
        <h3 className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          Notifications
        </h3>
        <p className="text-xs text-text-tertiary">Loading…</p>
      </section>
    );
  }

  return (
    <section className="space-y-3">
      <h3 className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
        Notifications
      </h3>
      <p className="text-xs text-text-secondary">
        OS notifications fire when a new message arrives and the Whisper
        window isn't focused. Permission is requested on the first send.
      </p>

      <ToggleRow
        label="Enable notifications"
        sub="Master switch. Off here means no banner, no sound."
        checked={prefs.enabled}
        onChange={(v) => update({ ...prefs, enabled: v })}
      />
      <ToggleRow
        label="Show message preview"
        sub="When off, banners read 'New message' with no content."
        checked={prefs.show_preview}
        onChange={(v) => update({ ...prefs, show_preview: v })}
        disabled={!prefs.enabled}
      />
      <ToggleRow
        label="Play notification sound"
        sub="Use the system default alert sound."
        checked={prefs.sound}
        onChange={(v) => update({ ...prefs, sound: v })}
        disabled={!prefs.enabled}
      />

      <div className="flex items-center gap-2 pt-1">
        <button
          onClick={test}
          disabled={!prefs.enabled}
          className="btn-secondary text-xs disabled:opacity-40"
        >
          Send test notification
        </button>
        {savingNote && (
          <span className="text-[11px] text-text-tertiary">{savingNote}</span>
        )}
      </div>
    </section>
  );
}

function ToggleRow({
  label,
  sub,
  checked,
  onChange,
  disabled = false,
}: {
  label: string;
  sub?: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={() => !disabled && onChange(!checked)}
      disabled={disabled}
      className={`w-full flex items-start justify-between gap-3 px-2 py-2 rounded-md
                  text-left transition-colors
                  ${disabled ? "opacity-40 cursor-not-allowed" : "hover:bg-bg-hover cursor-pointer"}`}
    >
      <div className="min-w-0">
        <div className="text-xs text-text-primary">{label}</div>
        {sub && <div className="text-[10px] text-text-tertiary mt-0.5">{sub}</div>}
      </div>
      <Switch on={checked} />
    </button>
  );
}

function Switch({ on }: { on: boolean }) {
  return (
    <span
      className={`mt-0.5 inline-flex h-4 w-7 flex-shrink-0 rounded-full border transition-colors
                  ${
                    on
                      ? "bg-accent-500 border-accent-600"
                      : "bg-bg-inset border-border-default"
                  }`}
    >
      <span
        className={`h-3 w-3 my-px rounded-full bg-white transition-transform
                    ${on ? "translate-x-3" : "translate-x-0.5"}`}
      />
    </span>
  );
}
