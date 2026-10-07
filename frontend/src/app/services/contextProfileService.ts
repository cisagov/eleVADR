import { authenticatedFetch, authApiUrl } from "./authService";
import type { DetectionConfigurationProfile } from "../components/DetectionConfiguration/types";
const PATH = "/api/v1/context-profiles";
async function message(r: Response) {
  try {
    const p = (await r.clone().json()) as { message?: string };
    if (p.message) return p.message;
  } catch {}
  return `Request failed with status ${r.status}`;
}
export async function listRemoteContextProfiles(): Promise<
  DetectionConfigurationProfile[]
> {
  const r = await authenticatedFetch(authApiUrl(PATH));
  if (!r.ok) throw new Error(await message(r));
  const p = (await r.json()) as { profiles?: DetectionConfigurationProfile[] };
  return p.profiles || [];
}
export async function saveRemoteContextProfile(
  profile: DetectionConfigurationProfile,
): Promise<DetectionConfigurationProfile> {
  const r = await authenticatedFetch(authApiUrl(PATH), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ profile }),
  });
  if (!r.ok) throw new Error(await message(r));
  return ((await r.json()) as { profile: DetectionConfigurationProfile })
    .profile;
}
export async function deleteRemoteContextProfile(id: string): Promise<void> {
  const r = await authenticatedFetch(
    authApiUrl(`${PATH}/${encodeURIComponent(id)}`),
    { method: "DELETE" },
  );
  if (!r.ok) throw new Error(await message(r));
}
