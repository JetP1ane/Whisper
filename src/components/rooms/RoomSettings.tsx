interface Props {
  name: string;
  description: string;
  onChangeName: (name: string) => void;
  onChangeDescription: (description: string) => void;
  isOwner: boolean;
  onDelete: () => void;
}

export function RoomSettings({
  name,
  description,
  onChangeName,
  onChangeDescription,
  isOwner,
  onDelete,
}: Props) {
  return (
    <div className="p-4 space-y-3">
      <h2 className="text-sm font-medium text-text-primary">Room settings</h2>
      <div>
        <label className="text-xs text-text-secondary">Name</label>
        <input
          value={name}
          onChange={(e) => onChangeName(e.target.value)}
          disabled={!isOwner}
          className="input mt-1 disabled:opacity-50"
        />
      </div>
      <div>
        <label className="text-xs text-text-secondary">Description</label>
        <textarea
          value={description}
          onChange={(e) => onChangeDescription(e.target.value)}
          disabled={!isOwner}
          rows={3}
          className="input mt-1 disabled:opacity-50 resize-none"
        />
      </div>
      {isOwner && (
        <button
          onClick={onDelete}
          className="btn w-full bg-status-err/10 text-status-err border border-status-err/30 hover:bg-status-err/20"
        >
          Delete room
        </button>
      )}
    </div>
  );
}
