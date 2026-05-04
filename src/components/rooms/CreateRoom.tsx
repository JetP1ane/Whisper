import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listContacts, Contact } from "../../hooks/useCrypto";

interface Props {
  onCreated: (id: string) => void;
  onCancel: () => void;
}

export function CreateRoom({ onCreated, onCancel }: Props) {
  const [name, setName] = useState("");
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    listContacts()
      .then(setContacts)
      .catch((e) => setError(String(e)));
  }, []);

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const submit = async () => {
    setError(null);
    setSubmitting(true);
    try {
      const id = await invoke<string>("room_create", {
        name: name.trim(),
        memberContactIds: Array.from(selected),
      });
      onCreated(id);
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const canSubmit = name.trim().length > 0 && selected.size > 0 && !submitting;

  return (
    <div className="p-4 space-y-3">
      <h2 className="text-sm font-medium text-text-primary">New room</h2>
      <input
        autoFocus
        value={name}
        onChange={(e) => setName(e.target.value)}
        placeholder="Room name"
        className="input"
      />

      <div>
        <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary mb-1.5">
          Members ({selected.size})
        </div>
        {contacts.length === 0 ? (
          <div className="text-xs text-text-tertiary italic">
            Add a contact first to invite them to a room.
          </div>
        ) : (
          <div className="max-h-[260px] overflow-y-auto rounded-md border border-border-subtle bg-bg-inset divide-y divide-border-subtle">
            {contacts.map((c) => {
              const on = selected.has(c.id);
              return (
                <button
                  key={c.id}
                  onClick={() => toggle(c.id)}
                  className={`w-full px-3 py-2 flex items-center justify-between text-left
                    ${on ? "bg-accent-500/10" : "hover:bg-bg-hover"}`}
                >
                  <div className="min-w-0">
                    <div className="text-sm text-text-primary font-mono truncate">
                      {c.alias}
                    </div>
                  </div>
                  <span
                    className={`w-4 h-4 rounded border flex items-center justify-center text-[10px]
                      ${
                        on
                          ? "bg-accent-500 border-accent-600 text-black"
                          : "border-border-default"
                      }`}
                  >
                    {on ? "✓" : ""}
                  </span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {error && <div className="text-xs text-status-err">{error}</div>}
      <div className="flex justify-end gap-2 pt-1">
        <button onClick={onCancel} className="btn-ghost text-xs">
          Cancel
        </button>
        <button
          disabled={!canSubmit}
          onClick={submit}
          className="btn-primary text-xs disabled:opacity-40"
        >
          {submitting ? "Creating…" : "Create"}
        </button>
      </div>
    </div>
  );
}
