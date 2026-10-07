import { authenticatedFetch, authApiUrl } from "./authService";
export interface AuditEvent {
  eventId: string;
  createdAt?: string | null;
  actorId?: string | null;
  actorUsername: string;
  action: string;
  result: string;
  targetType: string;
  targetId: string;
  metadata: Record<string, unknown>;
}
export async function listAuditEvents(
  scope: "mine" | "all" = "mine",
  limit = 50,
): Promise<AuditEvent[]> {
  const r = await authenticatedFetch(
    authApiUrl(`/api/v1/audit?scope=${scope}&limit=${limit}`),
  );
  if (!r.ok) throw new Error(`Unable to load activity (${r.status})`);
  return ((await r.json()) as { events: AuditEvent[] }).events;
}
