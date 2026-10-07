import { authenticatedFetch, authApiUrl } from "./authService";

export interface StorageUsage {
  ownerId?: string;
  username?: string;
  captureCount: number;
  captureBytes: number;
  reportCount: number;
  reportBytes: number;
  totalBytes: number;
  limitBytes: number;
  remainingBytes: number | null;
  retentionDays: number;
}
export interface StorageSummary extends StorageUsage {
  scope: "mine" | "all";
  users?: StorageUsage[];
  orphanFiles?: number;
}
async function message(r: Response) {
  try {
    const b = (await r.clone().json()) as { message?: string };
    if (b.message) return b.message;
  } catch {}
  return `Storage request failed (${r.status})`;
}
export async function getStorageSummary(
  scope: "mine" | "all" = "mine",
): Promise<StorageSummary> {
  const r = await authenticatedFetch(
    authApiUrl(`/api/v1/storage?scope=${scope}`),
    { cache: "no-store" },
  );
  if (!r.ok) throw new Error(await message(r));
  return r.json();
}
export async function cleanupStorage(removeOrphans = false): Promise<{
  expired: { expiredCaptures: number; bytesFreed: number };
  orphans: { orphanFiles: number; bytesFreed: number };
}> {
  const r = await authenticatedFetch(authApiUrl("/api/v1/storage/cleanup"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ removeOrphans }),
  });
  if (!r.ok) throw new Error(await message(r));
  return r.json();
}
