interface Member {
  contact_id: string;
  alias: string;
  role: "owner" | "member";
}

interface Props {
  members: Member[];
}

export function MemberList({ members }: Props) {
  return (
    <div className="flex flex-col">
      {members.map((m) => (
        <div
          key={m.contact_id}
          className="flex items-center justify-between px-3 py-2 hover:bg-bg-hover rounded-md"
        >
          <div className="flex items-center gap-2">
            <span className="w-6 h-6 rounded bg-bg-active border border-border-subtle" />
            <span className="text-sm text-text-primary">{m.alias}</span>
          </div>
          {m.role === "owner" && (
            <span className="px-1.5 py-0.5 rounded border border-accent-500/30 text-[10px] font-mono uppercase tracking-wider text-accent-400">
              owner
            </span>
          )}
        </div>
      ))}
    </div>
  );
}
