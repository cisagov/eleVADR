export interface ComparisonBucket { added: number; removed: number; changed: number; }
export interface FindingDelta {
  key: string;
  title: string;
  moduleId: string;
  change: "new" | "resolved" | "changed";
  severityBefore?: string;
  severityAfter?: string;
  confidenceBefore?: string;
  confidenceAfter?: string;
}
export interface ValueDelta { path: string; before: unknown; after: unknown; }
export interface ReportComparison {
  findings: ComparisonBucket;
  findingDeltas: FindingDelta[];
  contextChanges: string[];
  contextDeltas: ValueDelta[];
  moduleDeltas: ValueDelta[];
  assets: ComparisonBucket;
  services: ComparisonBucket;
  connections: ComparisonBucket;
  runtimeChanges: string[];
}
const obj=(v:unknown):Record<string,unknown> => v && typeof v==='object' && !Array.isArray(v) ? v as Record<string,unknown> : {};
const arr=(v:unknown):unknown[] => Array.isArray(v)?v:[];
const stable=(v:unknown):string => { if(Array.isArray(v)) return `[${v.map(stable).sort().join(',')}]`; if(v&&typeof v==='object') return `{${Object.entries(v as Record<string,unknown>).sort(([a],[b])=>a.localeCompare(b)).map(([k,x])=>`${JSON.stringify(k)}:${stable(x)}`).join(',')}}`; return JSON.stringify(v); };
const pickArray=(r:Record<string,unknown>, paths:string[][]):unknown[] => { for(const p of paths){let v:unknown=r; for(const k of p)v=obj(v)[k]; if(Array.isArray(v))return v;} return []; };
const findingKey=(v:unknown,i:number):string => { const x=obj(v); const evidence=obj(x.evidence); return String(x.finding_id??x.findingId??x.id??x.module_id??x.moduleId??`${x.title??x.name??'finding'}:${evidence.uid??evidence.zeek_uid??i}`); };
const genericKey=(v:unknown,i:number):string => { const x=obj(v); return String(x.id??x.ip??x.address??x.uid??x.name??x.title??`${i}:${stable(v)}`); };
function compareArrays(a:unknown[],b:unknown[]):ComparisonBucket{const am=new Map(a.map((v,i)=>[genericKey(v,i),stable(v)]));const bm=new Map(b.map((v,i)=>[genericKey(v,i),stable(v)]));let added=0,removed=0,changed=0;for(const [k,v] of bm){if(!am.has(k))added++;else if(am.get(k)!==v)changed++;}for(const k of am.keys())if(!bm.has(k))removed++;return{added,removed,changed};}
function diffValues(a:unknown,b:unknown,prefix='',out:ValueDelta[]=[]):ValueDelta[]{if(stable(a)===stable(b))return out;if(a&&b&&typeof a==='object'&&typeof b==='object'&&!Array.isArray(a)&&!Array.isArray(b)){const keys=new Set([...Object.keys(obj(a)),...Object.keys(obj(b))]);for(const k of [...keys].sort())diffValues(obj(a)[k],obj(b)[k],prefix?`${prefix}.${k}`:k,out);return out;}out.push({path:prefix||'value',before:a,after:b});return out;}
const text=(x:Record<string,unknown>,...keys:string[]):string|undefined=>{for(const k of keys){const v=x[k];if(v!==undefined&&v!==null&&String(v).trim())return String(v);}return undefined;};
function findingDeltas(a:unknown[],b:unknown[]):FindingDelta[]{const am=new Map(a.map((v,i)=>[findingKey(v,i),obj(v)]));const bm=new Map(b.map((v,i)=>[findingKey(v,i),obj(v)]));const out:FindingDelta[]=[];for(const [key,after] of bm){const before=am.get(key);const title=text(after,'title','name','finding')??key;const moduleId=text(after,'module_id','moduleId','detector_id','detectorId')??'';if(!before){out.push({key,title,moduleId,change:'new',severityAfter:text(after,'severity','risk'),confidenceAfter:text(after,'confidence')});continue;}if(stable(before)!==stable(after))out.push({key,title,moduleId,change:'changed',severityBefore:text(before,'severity','risk'),severityAfter:text(after,'severity','risk'),confidenceBefore:text(before,'confidence'),confidenceAfter:text(after,'confidence')});}for(const [key,before] of am){if(bm.has(key))continue;out.push({key,title:text(before,'title','name','finding')??key,moduleId:text(before,'module_id','moduleId','detector_id','detectorId')??'',change:'resolved',severityBefore:text(before,'severity','risk'),confidenceBefore:text(before,'confidence')});}return out.sort((x,y)=>x.change.localeCompare(y.change)||x.title.localeCompare(y.title));}
function moduleConfig(v:unknown):unknown{const x=obj(v);return x.module_overrides??x.moduleOverrides??x.modules??x.detector_overrides??x.detectorOverrides??{};}
export function compareReports(left:unknown,right:unknown):ReportComparison{const a=obj(left),b=obj(right);const findingsA=pickArray(a,[['arch_insights','detector_findings'],['findings']]);const findingsB=pickArray(b,[['arch_insights','detector_findings'],['findings']]);const contextA=a.detection_context??a.analysis_context??a.context??obj(a.metadata).detection_context??{};const contextB=b.detection_context??b.analysis_context??b.context??obj(b.metadata).detection_context??{};const assetsA=pickArray(a,[['devices'],['inventory','devices'],['assets']]);const assetsB=pickArray(b,[['devices'],['inventory','devices'],['assets']]);const servicesA=pickArray(a,[['services'],['inventory','services']]);const servicesB=pickArray(b,[['services'],['inventory','services']]);const conA=pickArray(a,[['connections'],['network','connections']]);const conB=pickArray(b,[['connections'],['network','connections']]);const runtimeKeys=['report_version','version','zeek_version','detector_version','engine_version'];const runtimeChanges=runtimeKeys.filter(k=>stable(a[k])!==stable(b[k])).map(k=>`${k}: ${String(a[k]??'—')} → ${String(b[k]??'—')}`);const contextDeltas=diffValues(contextA,contextB).slice(0,100);const moduleDeltas=diffValues(moduleConfig(contextA),moduleConfig(contextB)).slice(0,100);const deltas=findingDeltas(findingsA,findingsB);return{findings:{added:deltas.filter(x=>x.change==='new').length,removed:deltas.filter(x=>x.change==='resolved').length,changed:deltas.filter(x=>x.change==='changed').length},findingDeltas:deltas,contextChanges:contextDeltas.map(x=>x.path),contextDeltas,moduleDeltas,assets:compareArrays(assetsA,assetsB),services:compareArrays(servicesA,servicesB),connections:compareArrays(conA,conB),runtimeChanges};}
export function formatComparisonValue(value:unknown):string{if(value===undefined)return '—';if(value===null)return 'null';if(typeof value==='string')return value;try{return JSON.stringify(value);}catch{return String(value);}}
