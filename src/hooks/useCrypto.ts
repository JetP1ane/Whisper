import { invoke } from "@tauri-apps/api/core";

export interface IdentitySummary {
  alias: string;
  ed25519_public_hex: string;
  safety_number_hex_fingerprint: string;
}

export interface VaultSetupResult {
  recovery_phrase: string;
  alias: string;
}

export async function vaultSetup(passphrase: string): Promise<VaultSetupResult> {
  return invoke<VaultSetupResult>("vault_setup", { passphrase });
}

/**
 * Restore a vault from a BIP39 recovery phrase.
 *
 * M-14: when an existing vault is on disk this is a destructive wipe.
 * The backend now requires `confirmDestructiveWipe: true` so a stray
 * (or attacker-injected) call without the flag fails before any state
 * changes. Pass `true` only after a real user confirmation step.
 */
export async function vaultRecoverFromSeed(
  passphrase: string,
  recoveryPhrase: string,
  confirmDestructiveWipe: boolean,
): Promise<VaultSetupResult> {
  return invoke<VaultSetupResult>("vault_recover_from_seed", {
    passphrase,
    recoveryPhrase,
    confirmDestructiveWipe,
  });
}

export async function vaultViewRecoveryPhrase(
  passphrase: string,
): Promise<string | null> {
  return invoke<string | null>("vault_view_recovery_phrase", { passphrase });
}

export async function vaultUnlock(passphrase: string): Promise<void> {
  await invoke("vault_unlock", { passphrase });
}

export async function vaultLock(): Promise<void> {
  await invoke("vault_lock");
}

export async function getIdentity(): Promise<IdentitySummary> {
  return invoke<IdentitySummary>("identity_get");
}

export async function getInviteLink(): Promise<string> {
  return invoke<string>("identity_invite_link");
}

export async function publishBundle(): Promise<void> {
  await invoke("identity_publish_bundle");
}

export interface SafetyNumbers {
  digits: number[];
  formatted: string;
  hex_fingerprint: string;
}

export async function getSafetyNumbers(contactId: string): Promise<SafetyNumbers> {
  return invoke<SafetyNumbers>("contact_safety_numbers", { contactId });
}

export interface Contact {
  id: string;
  alias: string;
  ed25519_public: number[];
  x25519_public: number[];
  mlkem_public: number[];
  i2p_destination: string | null;
  verified: boolean;
  peer_has_verified_us: boolean;
  hide_until_verified: boolean;
  is_sealed: boolean;
  created_at: number;
  updated_at: number;
}

export async function addContactByAlias(alias: string): Promise<Contact> {
  return invoke<Contact>("contact_add_by_alias", { alias });
}

export async function addContactByLink(link: string): Promise<Contact> {
  return invoke<Contact>("contact_add_by_link", { link });
}

export async function listContacts(): Promise<Contact[]> {
  return invoke<Contact[]>("contact_list");
}

export async function acceptContactRequest(conversationId: string): Promise<void> {
  await invoke("contact_accept_request", { conversationId });
}

export async function declineContactRequest(conversationId: string): Promise<void> {
  await invoke("contact_decline_request", { conversationId });
}

export async function setContactVerified(
  contactId: string,
  verified: boolean,
): Promise<void> {
  await invoke("contact_verify", { id: contactId, verified });
}

