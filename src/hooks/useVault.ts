import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { VaultStatus } from "../stores/appStore";

export function useVault() {
  const [status, setStatus] = useState<VaultStatus | null>(null);

  const refresh = useCallback(async () => {
    const s = await invoke<VaultStatus>("vault_status");
    setStatus(s);
    return s;
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return { status, refresh };
}
