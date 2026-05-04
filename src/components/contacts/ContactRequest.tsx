interface Props {
  alias: string;
  onAccept: () => void;
  onDecline: () => void;
}

export function ContactRequest({ alias, onAccept, onDecline }: Props) {
  return (
    <div className="px-3 py-2 rounded-md bg-bg-raised border border-border-subtle flex items-center gap-3">
      <div className="flex-1 min-w-0">
        <div className="text-sm text-text-primary truncate">{alias}</div>
        <div className="text-[10px] font-mono uppercase tracking-wider text-text-tertiary">
          contact request
        </div>
      </div>
      <button onClick={onDecline} className="btn-ghost text-xs">
        Decline
      </button>
      <button onClick={onAccept} className="btn-primary text-xs">
        Accept
      </button>
    </div>
  );
}
