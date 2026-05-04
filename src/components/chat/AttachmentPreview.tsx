import { formatBytes } from "../../utils/formatters";

interface Props {
  filename: string;
  size: number;
  mime: string;
  onRemove?: () => void;
}

export function AttachmentPreview({ filename, size, mime, onRemove }: Props) {
  const isImage = mime.startsWith("image/");
  return (
    <div className="flex items-center gap-2 px-2 py-1.5 rounded-md bg-bg-raised border border-border-subtle">
      <div className={`w-7 h-7 rounded ${isImage ? "bg-accent-900" : "bg-bg-active"}`} />
      <div className="flex flex-col min-w-0">
        <span className="text-xs text-text-primary truncate">{filename}</span>
        <span className="text-[10px] text-text-tertiary">{formatBytes(size)}</span>
      </div>
      {onRemove && (
        <button onClick={onRemove} className="ml-2 text-text-tertiary hover:text-text-primary text-xs">
          ×
        </button>
      )}
    </div>
  );
}
