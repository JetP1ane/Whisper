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

interface AppState {
  vault: VaultStatus | null;
  identityAlias: string | null;
  refreshStatus: () => Promise<VaultStatus>;
}

export const useAppStore = create<AppState>((set) => ({
  vault: null,
  identityAlias: null,
  refreshStatus: async () => {
    const status = await invoke<VaultStatus>("vault_status");
    set({ vault: status });
    return status;
  },
}));
