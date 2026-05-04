import { create } from "zustand";
import { invoke } from "@tauri-apps/api/core";

export type HardwareTier =
  | "secure_enclave_biometric"
  | "secure_enclave"
  | "software_only"
  | "none";

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
  hardware_tier: HardwareTier;
}

export interface RelayStatus {
  url: string | null;
  connected: boolean;
  frame_counters: {
    frames_sent: number;
    frames_received: number;
    bytes_sent: number;
    bytes_received: number;
  };
}

interface AppState {
  vault: VaultStatus | null;
  relay: RelayStatus | null;
  identityAlias: string | null;
  refreshStatus: () => Promise<VaultStatus>;
  refreshRelay: () => Promise<RelayStatus | null>;
}

export const useAppStore = create<AppState>((set) => ({
  vault: null,
  relay: null,
  identityAlias: null,
  refreshStatus: async () => {
    const status = await invoke<VaultStatus>("vault_status");
    set({ vault: status });
    return status;
  },
  refreshRelay: async () => {
    try {
      const r = await invoke<RelayStatus>("relay_status");
      set({ relay: r });
      return r;
    } catch {
      return null;
    }
  },
}));
