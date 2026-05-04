import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface Props {
  onAdded: () => void;
  onCancel: () => void;
}

export function AddContact({ onAdded, onCancel }: Props) {
  const [alias, setAlias] = useState("");
  const [nickname, setNickname] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const submit = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const trimmedNick = nickname.trim();
      await invoke("contact_add_by_alias", {
        alias,
        nickname: trimmedNick.length > 0 ? trimmedNick : null,
      });
      onAdded();
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-4 space-y-3">
      <h2 className="text-sm font-medium text-text-primary">Add contact</h2>
      <p className="text-xs text-text-secondary">
        Enter the three-word Whisper ID. We'll look up their public bundle and verify the
        signature.
      </p>
      <div>
        <label className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          Whisper ID
        </label>
        <input
          autoFocus
          value={alias}
          onChange={(e) => setAlias(e.target.value)}
          placeholder="amber-falcon-seven"
          className="input font-mono mt-1"
        />
      </div>
      <div>
        <label className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          Nickname <span className="lowercase text-text-tertiary">(optional)</span>
        </label>
        <input
          value={nickname}
          onChange={(e) => setNickname(e.target.value)}
          placeholder="Mark"
          className="input mt-1"
        />
        <p className="text-[10px] text-text-tertiary mt-1">
          Local-only. The peer never sees this name; you'll see it instead of the Whisper ID.
        </p>
      </div>
      {error && (
        <div className="text-xs text-status-err">{error}</div>
      )}
      <div className="flex justify-end gap-2 pt-1">
        <button onClick={onCancel} className="btn-ghost text-xs">
          Cancel
        </button>
        <button
          disabled={!alias || submitting}
          onClick={submit}
          className="btn-primary text-xs disabled:opacity-40"
        >
          {submitting ? "Looking up…" : "Add"}
        </button>
      </div>
    </div>
  );
}
