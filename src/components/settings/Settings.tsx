import { useState } from "react";
import { SecurityDashboard } from "./SecurityDashboard";
import { RelayConfig } from "./RelayConfig";
import { NotificationsConfig } from "./NotificationsConfig";

interface Props {
  onClose: () => void;
}

type Section = "security" | "relay" | "notifications";

export function Settings({ onClose }: Props) {
  const [section, setSection] = useState<Section>("security");

  return (
    <div className="fixed inset-0 z-40 bg-black/70 flex items-center justify-center animate-fade-in">
      <div className="w-[720px] h-[80vh] panel border rounded-xl flex overflow-hidden">
        <nav className="w-[180px] border-r border-border-subtle p-3 space-y-1">
          <NavItem
            label="Security"
            active={section === "security"}
            onClick={() => setSection("security")}
          />
          <NavItem
            label="Relay"
            active={section === "relay"}
            onClick={() => setSection("relay")}
          />
          <NavItem
            label="Notifications"
            active={section === "notifications"}
            onClick={() => setSection("notifications")}
          />
        </nav>
        <div className="flex-1 flex flex-col">
          <header className="h-[44px] flex items-center justify-between px-4 border-b border-border-subtle">
            <span className="text-sm text-text-primary">Settings</span>
            <button onClick={onClose} className="btn-ghost text-xs">
              Close
            </button>
          </header>
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {section === "security" && <SecurityDashboard />}
            {section === "relay" && <RelayConfig />}
            {section === "notifications" && <NotificationsConfig />}
          </div>
        </div>
      </div>
    </div>
  );
}

function NavItem({
  label,
  active,
  onClick,
}: {
  label: string;
  active?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-2 py-1.5 rounded-md text-xs ${
        active
          ? "bg-bg-active text-text-primary"
          : "text-text-secondary hover:bg-bg-hover"
      }`}
    >
      {label}
    </button>
  );
}
