import { authenticatedFetch } from "./authService";

export interface RetainedCaptureSummary {
  captureId: string; filename: string; sha256: string; sizeBytes: number; createdAt: string; lastUsedAt: string; expiresAt?: string | null;
}
function api(path=""): string {
  const env=(import.meta as ImportMeta & {env?:Record<string,string|undefined>}).env;
  const configured=[env?.VITE_PCAP_ANALYSIS_URL,env?.VITE_DETECTION_ANALYSIS_URL].map(v=>v?.trim()).find(Boolean);
  if(configured){try{return `${new URL(configured,window.location.origin).origin}/api/v1/captures${path}`;}catch{/* same-origin */}}
  return `/api/v1/captures${path}`;
}
async function msg(r:Response){try{const p=await r.clone().json() as {message?:unknown};if(typeof p.message==="string")return p.message;}catch{}return `Capture request failed with status ${r.status}`;}
export async function listRetainedCaptures():Promise<RetainedCaptureSummary[]>{const r=await authenticatedFetch(api(),{cache:"no-store"});if(!r.ok)throw new Error(await msg(r));const p=await r.json() as {captures?:RetainedCaptureSummary[]};return Array.isArray(p.captures)?p.captures:[];}
export async function deleteRetainedCapture(id:string):Promise<void>{const r=await authenticatedFetch(api(`/${encodeURIComponent(id)}`),{method:"DELETE"});if(!r.ok)throw new Error(await msg(r));}
export async function analyzeRetainedCapture(id:string,profile:unknown):Promise<unknown>{
  const r=await authenticatedFetch(api(`/${encodeURIComponent(id)}/analyze`),{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({profile})});if(!r.ok)throw new Error(await msg(r));const p=await r.json() as {jobId?:string};if(!p.jobId)throw new Error("Backend did not return an analysis job ID.");
  const env=(import.meta as ImportMeta & {env?:Record<string,string|undefined>}).env; const configured=env?.VITE_PCAP_ANALYSIS_URL?.trim(); const base=configured||"/api/v1/pcap-analysis"; const status=`${base.replace(/\/$/,"")}/${encodeURIComponent(p.jobId)}`;
  for(;;){await new Promise(res=>window.setTimeout(res,650));const s=await authenticatedFetch(status,{cache:"no-store"});const body=await s.json() as {status?:string;message?:string;result?:unknown};if(!s.ok)throw new Error(body.message||`Analysis status failed (${s.status})`);if(body.status==="failed"||body.status==="canceled")throw new Error(body.message||"Retained capture analysis failed.");if(body.status==="completed")return body.result;}
}
