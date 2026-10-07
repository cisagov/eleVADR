import { authenticatedFetch, authApiUrl } from "./authService";

export interface PlatformUser { id:string; username:string; email:string; role:string; disabled:boolean; created?:string|null; lastLogin?:string|null; }

async function message(response: Response): Promise<string> {
  try { const body = await response.clone().json() as {message?:string}; if (body.message) return body.message; } catch {}
  return `Request failed with status ${response.status}`;
}
export async function changeOwnPassword(currentPassword:string,newPassword:string): Promise<void> {
  const r=await authenticatedFetch(authApiUrl("/auth/password"),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({currentPassword,newPassword})});
  if(!r.ok) throw new Error(await message(r));
}
export async function listUsers(): Promise<PlatformUser[]> { const r=await authenticatedFetch(authApiUrl("/api/v1/users")); if(!r.ok) throw new Error(await message(r)); return ((await r.json()) as {users:PlatformUser[]}).users; }
export async function createUser(input:{username:string;password:string;email?:string;role:string}): Promise<PlatformUser> { const r=await authenticatedFetch(authApiUrl("/api/v1/users"),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(input)}); if(!r.ok) throw new Error(await message(r)); return ((await r.json()) as {user:PlatformUser}).user; }
export async function updateUser(id:string,input:{role?:string;disabled?:boolean}): Promise<PlatformUser> { const r=await authenticatedFetch(authApiUrl(`/api/v1/users/${encodeURIComponent(id)}`),{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify(input)}); if(!r.ok) throw new Error(await message(r)); return ((await r.json()) as {user:PlatformUser}).user; }
