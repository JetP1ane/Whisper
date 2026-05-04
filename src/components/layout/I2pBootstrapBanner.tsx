import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface I2pStatus {
  ready: boolean;
  destination: string;
  session_id: string;
  sam_addr: string;
  log_path: string;
  cached_outbound_streams: number;
}

/**
 * Top-of-window banner that surfaces I2P bootstrap progress prominently.
 *
 * I2P's first-launch bootstrap (reseed → tunnels → encrypted leaseset
 * publish → master STREAM session) takes 30-90 seconds end-to-end. Until
 * this completes, the user can't send or receive anything peer-to-peer.
 * Without a visible signal, the app feels broken.
 *
 * The banner:
 *  - Polls `i2p_status` every 1 second
 *  - Tracks elapsed time since first observed not-ready
 *  - Shows progressive phase labels matching the actual i2pd boot stages
 *  - Auto-dismisses (slide-up animation) the moment `ready` flips true
 *  - Shows an explicit error state if bootstrap exceeds 2 minutes
 */
export function I2pBootstrapBanner() {
  const [status, setStatus] = useState<I2pStatus | null>(null);
  const [elapsedSecs, setElapsedSecs] = useState(0);
  const [hidden, setHidden] = useState(false);
  const startedAt = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const s = await invoke<I2pStatus>("i2p_status");
        if (cancelled) return;
        setStatus(s);
        if (!s.ready) {
          if (startedAt.current === null) {
            startedAt.current = Date.now();
          }
          setElapsedSecs(Math.floor((Date.now() - startedAt.current) / 1000));
        } else {
          // Reset for any future not-ready window (e.g. after i2pd restart).
          startedAt.current = null;
          setElapsedSecs(0);
          // Brief delay before hiding so the user sees the green "Connected"
          // state, then the banner slides away.
          setTimeout(() => {
            if (!cancelled) setHidden(true);
          }, 1500);
        }
      } catch {
        /* ignore — vault may be locking, we'll retry */
      }
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  // Hidden once ready+1.5s elapsed, OR before any status loaded.
  if (hidden) return null;
  if (status === null) return null;

  // Connected — render briefly with the success state, then unmount.
  if (status.ready) {
    return (
      <div className="px-4 py-2 bg-status-ok/10 border-b border-status-ok/30 flex items-center gap-3 animate-fade-in">
        <span className="w-2 h-2 rounded-full bg-status-ok shrink-0 animate-pulse" />
        <span className="text-xs text-text-primary">
          Private network connected
        </span>
        <span className="text-[10px] font-mono text-text-tertiary">
          {status.cached_outbound_streams} streams
        </span>
      </div>
    );
  }

  // Bootstrapping — staged messages by elapsed time.
  const phase = phaseLabel(elapsedSecs);
  const isError = elapsedSecs >= 120;
  return (
    <div
      className={
        "px-4 py-2 border-b flex items-center gap-3 " +
        (isError
          ? "bg-status-err/10 border-status-err/30"
          : "bg-status-warn/10 border-status-warn/30")
      }
    >
      {isError ? (
        <span className="w-2 h-2 rounded-full bg-status-err shrink-0" />
      ) : (
        <span className="w-2 h-2 rounded-full bg-status-warn shrink-0 animate-pulse" />
      )}
      <span className="text-xs text-text-primary flex-1">{phase}</span>
      <span className="text-[10px] font-mono text-text-tertiary tabular-nums">
        {elapsedSecs}s
      </span>
      {isError && (
        <a
          href="#"
          onClick={(e) => {
            e.preventDefault();
            // Surface the i2pd log path so the user can debug.
            // (Settings → Security shows the same path.)
          }}
          className="text-[10px] font-mono text-status-err hover:underline"
        >
          troubleshoot
        </a>
      )}
    </div>
  );
}

function phaseLabel(elapsedSecs: number): string {
  if (elapsedSecs >= 120) {
    return "I2P network is taking longer than expected. Check Settings → Security for diagnostics.";
  }
  if (elapsedSecs >= 60) {
    return "Bootstrapping into the I2P network… first launch can take up to 2 minutes";
  }
  if (elapsedSecs >= 30) {
    return "Building anonymous tunnels…";
  }
  if (elapsedSecs >= 10) {
    return "Connecting to I2P peers…";
  }
  return "Starting private network…";
}
