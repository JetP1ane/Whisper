import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface I2pStatus {
  ready: boolean;
  destination: string;
  session_id: string;
  sam_addr: string;
  log_path: string;
  cached_outbound_streams: number;
  bootstrap_attempt: number;
  bootstrap_last_error: string | null;
  bootstrap_in_flight: boolean;
}

/**
 * Top-of-window banner that surfaces I2P bootstrap progress.
 *
 * Three principles:
 *  1. The Rust side retries forever — port collisions, "SAM bridge not
 *     ready yet", transient tunnel failures all clear in seconds. We
 *     surface a single "starting up" state across all of them; never
 *     "error" / "failed" wording in the user-visible banner.
 *  2. Elapsed time is monotonic (since the first attempt), not
 *     per-attempt — fewer surprising counter resets while waiting.
 *  3. The full backend error string is still attached as a tooltip
 *     on the message text, for dev / power-user inspection.
 */
export function I2pBootstrapBanner() {
  const [status, setStatus] = useState<I2pStatus | null>(null);
  const [elapsedSecs, setElapsedSecs] = useState(0);
  const [hidden, setHidden] = useState(false);
  // We track total elapsed since the *first* bootstrap attempt, not
  // per-attempt — a monotonic counter. Resets when SAM goes ready.
  const bootstrapStartedAt = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const s = await invoke<I2pStatus>("i2p_status");
        if (cancelled) return;
        setStatus(s);
        if (s.ready) {
          bootstrapStartedAt.current = null;
          setElapsedSecs(0);
          setTimeout(() => {
            if (!cancelled) setHidden(true);
          }, 1500);
          return;
        }
        if (bootstrapStartedAt.current === null) {
          bootstrapStartedAt.current = Date.now();
        }
        setElapsedSecs(
          Math.floor((Date.now() - bootstrapStartedAt.current) / 1000),
        );
      } catch {
        /* vault locking — try again next tick */
      }
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  if (hidden) return null;
  if (status === null) return null;

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

  const lastErr = status.bootstrap_last_error;
  const phase = phaseLabel(elapsedSecs);
  // The Rust side retries forever (port races, transient tunnel failures,
  // and "i2pd booted but SAM not ready yet" all clear within seconds).
  // We deliberately don't expose those transient errors to the user —
  // every bootstrap state below ready is a normal "starting up" state
  // and renders the same warm progress banner. The full error string
  // is still available on hover for power users / dev diagnostics.
  return (
    <div
      className="px-4 py-2 border-b flex items-center gap-3 bg-status-warn/10 border-status-warn/30"
    >
      <span className="w-2 h-2 rounded-full shrink-0 bg-status-warn animate-pulse" />
      <span
        className="text-xs text-text-primary flex-1 truncate"
        title={lastErr ?? undefined}
      >
        {phase}
      </span>
      <span className="text-[10px] font-mono text-text-tertiary tabular-nums">
        {elapsedSecs}s
      </span>
    </div>
  );
}

function phaseLabel(elapsedSecs: number): string {
  if (elapsedSecs >= 120) {
    return "Still connecting to the private network…";
  }
  if (elapsedSecs >= 60) {
    return "Building anonymous tunnels — first launch can take a minute…";
  }
  if (elapsedSecs >= 30) {
    return "Building anonymous tunnels…";
  }
  if (elapsedSecs >= 10) {
    return "Connecting to peers…";
  }
  return "Starting private network…";
}
