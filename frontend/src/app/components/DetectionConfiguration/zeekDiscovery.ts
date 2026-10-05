import {MODULE_REQUIREMENTS} from './moduleCatalog';
import {createEmptyProfile} from './defaultProfile';
import type {Asset, CommunicationRule, DetectionProfile, ReadinessItem, ScanProgress, Segment, TrustedService} from './types';

type Row = Record<string, unknown>;
const ICS_LOGS = new Set(['bacnet','cip','dnp3','enip','modbus','s7comm','snmp']);
const PRIVATE4 = [/^10\./,/^192\.168\./,/^172\.(1[6-9]|2\d|3[01])\./];

function logTypeOf(name:string):string {
  const base = name.split('/').pop()!.replace(/\.gz$/i,'').replace(/\.log$/i,'').toLowerCase();
  return base;
}
function s(v:unknown):string { return v == null ? '' : String(v); }
function n(v:unknown):number|null { const x=Number(v); return Number.isFinite(x) ? x : null; }
function first(row:Row,...keys:string[]):unknown { for(const k of keys) if(row[k]!==undefined && row[k]!==null && row[k]!=='') return row[k]; return undefined; }
function ip4(v:string):boolean { return /^\d{1,3}(\.\d{1,3}){3}$/.test(v); }
function isPrivate(ip:string):boolean { return PRIVATE4.some(r=>r.test(ip)); }
function cidr24(ip:string):string|null { if(!ip4(ip)||!isPrivate(ip)) return null; const p=ip.split('.'); return `${p[0]}.${p[1]}.${p[2]}.0/24`; }
function ts(row:Row):number|null { return n(first(row,'ts','timestamp','time')); }
function sourceIp(row:Row):string { return s(first(row,'id.orig_h','source_ip','src','src_ip','client_addr','client')); }
function destIp(row:Row):string { return s(first(row,'id.resp_h','destination_ip','dst','dst_ip','server_addr','server')); }
function destPort(row:Row):number|null { return n(first(row,'id.resp_p','destination_port','dst_port','port')); }
function proto(row:Row):string { return s(first(row,'proto','protocol')).toLowerCase(); }
function service(row:Row):string { return s(first(row,'service','application','app')).toLowerCase(); }

async function parseZeekFile(file:File):Promise<Row[]> {
  const text = await file.text();
  const lines = text.split(/\r?\n/).filter(Boolean);
  if(!lines.length) return [];
  const firstData = lines.find(l=>!l.startsWith('#')) || '';
  if(firstData.trim().startsWith('{')) {
    const out:Row[]=[];
    for(const line of lines){ if(line.startsWith('#')) continue; try{out.push(JSON.parse(line));}catch{} }
    return out;
  }
  let fields:string[]=[]; let sep='\t'; const out:Row[]=[];
  for(const line of lines){
    if(line.startsWith('#separator ')){ const raw=line.slice(11); if(raw.startsWith('\\x')) sep=String.fromCharCode(parseInt(raw.slice(2),16)); continue; }
    if(line.startsWith('#fields')){ fields=line.split(sep).slice(1); continue; }
    if(line.startsWith('#')) continue;
    const parts=line.split(sep);
    if(!fields.length) continue;
    const row:Row={}; fields.forEach((f,i)=>row[f]=parts[i]==='-'?null:parts[i]); out.push(row);
  }
  return out;
}

function bump(map:Map<string,number>,key:string){ if(key) map.set(key,(map.get(key)||0)+1); }
function ensureEvidence(map:Map<string,Map<string,number>>,ip:string,kind:string){ if(!ip)return; if(!map.has(ip))map.set(ip,new Map()); bump(map.get(ip)!,kind); }
function confidence(count:number):'low'|'medium'|'high' { return count>=20?'high':count>=5?'medium':'low'; }
function addTrusted(asset:Asset|undefined, service:TrustedService){ if(asset && !asset.trustedServices.includes(service)) asset.trustedServices.push(service); }

export async function discoverFromFiles(files:File[], onProgress?: (p:ScanProgress)=>void):Promise<DetectionProfile> {
  const profile=createEmptyProfile('Discovered Network Profile');
  const hostCounts=new Map<string,number>(), hostEvidence=new Map<string,Map<string,number>>(), pairCounts=new Map<string,number>();
  const dnsServers=new Map<string,number>(), ntpServers=new Map<string,number>(), dhcpServers=new Map<string,number>();
  const vlanIds=new Set<number>(), innerVlanIds=new Set<number>(), services=new Set<string>(), segments=new Map<string,number>();
  const pairMeta=new Map<string,{src:string;dst:string;protocol:string;port:number|null;service:string|null}>();
  const hostnames=new Map<string,string>();
  let captureStart:number|null=null,captureEnd:number|null=null;
  const recognized:File[]=[];
  for(const f of files){ const lt=logTypeOf(f.name); if(f.name.toLowerCase().endsWith('.log') || f.type.includes('json') || MODULE_REQUIREMENTS.some(m=>m.requiredLogs.includes(lt))) recognized.push(f); }
  let idx=0;
  for(const file of recognized){
    onProgress?.({current:++idx,total:recognized.length,fileName:file.name});
    const lt=logTypeOf(file.name); const rows=await parseZeekFile(file);
    profile.discovery.files.push({name:file.name,logType:lt,rows:rows.length});
    for(const row of rows){
      const t=ts(row); if(t!==null){captureStart=captureStart===null?t:Math.min(captureStart,t);captureEnd=captureEnd===null?t:Math.max(captureEnd,t);}
      const src=sourceIp(row), dst=destIp(row);
      for(const ip of [src,dst]) if(ip){ bump(hostCounts,ip); const c=cidr24(ip); if(c)bump(segments,c); }
      if(ICS_LOGS.has(lt)){ for(const ip of [src,dst]) ensureEvidence(hostEvidence,ip,lt); }
      if(lt==='conn' && src && dst){
        const p=destPort(row), pr=proto(row), sv=service(row)||null; if(sv)services.add(sv);
        const key=`${src}|${dst}|${pr}|${p??''}|${sv??''}`; bump(pairCounts,key); pairMeta.set(key,{src,dst,protocol:pr,port:p,service:sv});
        const v=n(first(row,'vlan','vlan_id')); if(v!==null)vlanIds.add(v); const iv=n(first(row,'inner_vlan','inner_vlan_id')); if(iv!==null)innerVlanIds.add(iv);
      }
      if(lt==='dns'){
        const server=dst || s(first(row,'resolver','server')); if(server)bump(dnsServers,server);
        const q=s(first(row,'query','qname')); const answers=first(row,'answers','answer');
        if(q && answers){ const arr=Array.isArray(answers)?answers:String(answers).split(','); for(const a0 of arr){const a=String(a0).trim(); if(ip4(a))hostnames.set(a,q);} }
      }
      if(lt==='ntp'){ const server=dst || s(first(row,'server')); if(server)bump(ntpServers,server); }
      if(lt==='dhcp'){ const server=s(first(row,'server_addr','server','id.resp_h','destination_ip')); if(server)bump(dhcpServers,server); }
    }
  }
  profile.discovery.scannedAt=new Date().toISOString(); profile.discovery.logTypes=[...new Set(profile.discovery.files.map(x=>x.logType))].sort();
  profile.discovery.captureStart=captureStart; profile.discovery.captureEnd=captureEnd; profile.discovery.observedHosts=hostCounts.size; profile.discovery.observedPairs=pairCounts.size;
  if(!recognized.length) profile.discovery.warnings.push('No Zeek log files were recognized.');

  const segs:Segment[]=[...segments.entries()].sort((a,b)=>b[1]-a[1]).map(([cidr,count],i)=>({id:`segment-${i+1}`,name:`Observed ${cidr}`,cidr,role:'unknown',purdueLevel:null,vlanId:null,addressing:'unknown',dhcpAllowed:null,ipv6Allowed:null,source:'Zeek conn/protocol logs',confidence:confidence(count),confirmed:false,reason:'Private IPv4 hosts observed in this /24. Network role and boundary must be confirmed by the user.',observations:count}));
  profile.environment.segments=segs;

  const infrastructureIps=new Set([...dnsServers.keys(),...ntpServers.keys(),...dhcpServers.keys()]);
  for(const ip of infrastructureIps) if(!hostCounts.has(ip)) hostCounts.set(ip,0);
  const assets:Asset[]=[...hostCounts.entries()].sort((a,b)=>b[1]-a[1]).map(([ip,count])=>{
    const ev=Object.fromEntries(hostEvidence.get(ip)||[]); const likelyOt=Object.keys(ev).length>0;
    const seg=segs.find(x=>x.cidr===cidr24(ip));
    return {ip,hostname:hostnames.get(ip)||null,assetType:likelyOt?'OT/ICS participant':infrastructureIps.has(ip)?'Infrastructure':'unknown',role:infrastructureIps.has(ip)?'Infrastructure':'unknown',segmentId:seg?.id||null,purdueLevel:null,trustedServices:[],observations:count,evidence:ev,source:'Zeek logs',confidence:likelyOt?'medium':infrastructureIps.has(ip)?'medium':'low',confirmed:false,reason:likelyOt?`Observed in ICS protocol logs: ${Object.keys(ev).join(', ')}`:infrastructureIps.has(ip)?'Observed providing common infrastructure services; trust must be confirmed.':'Observed as a network endpoint; device role cannot be determined from traffic alone.'};
  });
  for(const [ip] of dnsServers) addTrusted(assets.find(x=>x.ip===ip),'DNS');
  for(const [ip] of ntpServers) addTrusted(assets.find(x=>x.ip===ip),'NTP');
  for(const [ip] of dhcpServers) addTrusted(assets.find(x=>x.ip===ip),'DHCP');
  profile.environment.assets=assets;
  profile.environment.observedVlanIds=[...vlanIds].sort((a,b)=>a-b); profile.environment.observedInnerVlanIds=[...innerVlanIds].sort((a,b)=>a-b); profile.environment.observedServices=[...services].sort();

  const rules:CommunicationRule[]=[...pairCounts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,1000).map(([key,count],i)=>{
    const m=pairMeta.get(key)!;
    return {id:`observed-rule-${i+1}`,sourceRef:m.src,destinationRef:m.dst,scope:'host-host',protocol:m.protocol||'any',destinationPort:m.port,service:m.service,purpose:'Observed communication',allowed:false,confirmed:false,source:'conn.log',confidence:confidence(count),reason:'Observed communication is a candidate only; presence does not imply authorization.',observations:count};
  });
  profile.environment.communicationRules=rules;
  profile.readiness=evaluateReadiness(profile);
  return profile;
}

export function evaluateReadiness(profile:DetectionProfile):ReadinessItem[] {
  const logs=new Set(profile.discovery.logTypes); const e=profile.environment;
  const confirmedSegments=e.segments.filter(x=>x.confirmed), confirmedAssets=e.assets.filter(x=>x.confirmed);
  const approvedRules=e.communicationRules.filter(x=>x.confirmed&&x.allowed);
  const trusted=(service:TrustedService)=>confirmedAssets.filter(x=>x.trustedServices.includes(service));
  return MODULE_REQUIREMENTS.map(m=>{
    const issues:string[]=[];
    if(m.requiredLogs.length && !m.requiredLogs.some(x=>logs.has(x))) issues.push(`No expected Zeek log observed (${m.requiredLogs.join(', ')}).`);
    for(const c of m.context){
      if(c==='segments'&&!confirmedSegments.length)issues.push('Confirm network segment definitions.');
      if(c==='assets'&&!confirmedAssets.length)issues.push('Confirm asset/infrastructure entries.');
      if(c==='trusted_dns'&&!trusted('DNS').length)issues.push('Mark trusted DNS infrastructure.');
      if(c==='trusted_ntp'&&!trusted('NTP').length)issues.push('Mark trusted NTP infrastructure.');
      if(c==='trusted_dhcp'&&!trusted('DHCP').length)issues.push('Mark expected DHCP infrastructure.');
      if(c==='approved_pairs'&&!approvedRules.length)issues.push('Review/define approved communication rules.');
      if(c==='vlan_policy'&&confirmedSegments.every(x=>x.vlanId===null))issues.push('Confirm expected VLAN IDs on network segments.');
      if(c==='ipv4_only_policy'&&confirmedSegments.every(x=>x.ipv6Allowed===null))issues.push('State whether applicable OT segments permit IPv6.');
      if(c==='baseline'&&profile.discovery.captureStart!==null&&profile.discovery.captureEnd!==null&&(profile.discovery.captureEnd-profile.discovery.captureStart)<profile.detectionTuning.baselineSeconds)issues.push('Capture may be shorter than the configured baseline duration.');
    }
    const missingLog=issues.some(x=>x.startsWith('No expected Zeek log'));
    return {moduleId:m.id,name:m.name,status:missingLog?'info':issues.length?'warning':'ready',issues};
  });
}
