import {createEmptyProfile} from './defaultProfile';
import type {Asset, CommunicationRule, DetectionProfile, TrustedService} from './types';

const KEY = 'elevadr.detectionProfile.v2';
const LEGACY_KEY = 'elevadr.detectionProfile.v1';
const clone=<T,>(x:T):T=>JSON.parse(JSON.stringify(x));

function mergeTrustedService(assets: Asset[], ip: string, service: TrustedService, provenance?: {source?:string; confidence?:'low'|'medium'|'high'; reason?:string; observations?:number}) {
  if (!ip) return;
  let asset = assets.find(x=>x.ip===ip);
  if (!asset) {
    asset = {
      ip, hostname:null, assetType:'Infrastructure', role:'Infrastructure', segmentId:null, purdueLevel:null,
      trustedServices:[], evidence:{}, confirmed:false,
      source:provenance?.source || 'legacy profile', confidence:provenance?.confidence || 'high',
      reason:provenance?.reason || 'Migrated from legacy trusted infrastructure list.', observations:provenance?.observations,
    };
    assets.push(asset);
  }
  if (!asset.trustedServices.includes(service)) asset.trustedServices.push(service);
}

export function migrateProfile(input: unknown): DetectionProfile {
  const raw:any = clone(input as any);
  if (raw?.schemaVersion===2 && raw?.environment?.communicationRules) return raw as DetectionProfile;

  const out=createEmptyProfile(raw?.profile?.name || 'Migrated Network Profile');
  if (!raw || typeof raw!=='object') return out;
  out.profile={...out.profile,...(raw.profile||{}),updatedAt:new Date().toISOString()};
  out.selectedModules=Array.isArray(raw.selectedModules)?raw.selectedModules:out.selectedModules;
  out.discovery={...out.discovery,...(raw.discovery||{})};
  out.modulePolicies={...out.modulePolicies,...(raw.modulePolicies||{})};
  out.readiness=Array.isArray(raw.readiness)?raw.readiness:[];

  const env=raw.environment||{};
  out.environment.segments=(env.segments||[]).map((s:any)=>({...s}));
  out.environment.assets=(env.assets||[]).map((a:any)=>({...a,trustedServices:Array.isArray(a.trustedServices)?a.trustedServices:[]}));
  out.environment.observedVlanIds=env.observedVlanIds||[];
  out.environment.observedInnerVlanIds=env.observedInnerVlanIds||[];
  out.environment.observedServices=env.observedServices||[];

  const infra=env.trustedInfrastructure||{};
  const addCandidates=(items:any[], service:TrustedService)=>{
    for(const item of items||[]){
      const value=String(item?.value??item??'');
      mergeTrustedService(out.environment.assets,value,service,item);
      const a=out.environment.assets.find(x=>x.ip===value);
      if(a && item?.confirmed) a.confirmed=true;
    }
  };
  addCandidates(infra.dnsResolvers,'DNS');
  addCandidates(infra.ntpServers,'NTP');
  addCandidates(infra.dhcpServers,'DHCP');
  addCandidates(infra.managementHosts,'Management');

  const ac=env.approvedCommunications||{};
  const rules:CommunicationRule[]=[];
  const addRule=(sourceRef:string,destinationRef:string,scope:CommunicationRule['scope'],protocol='any',allowed=true,confirmed=true,reason='Migrated from legacy communication configuration.')=>{
    rules.push({id:`rule-${rules.length+1}`,sourceRef,destinationRef,scope,protocol,destinationPort:null,service:null,purpose:'',allowed,confirmed,source:'legacy profile',confidence:'high',reason});
  };
  for(const p of ac.observedPairCandidates||[]){
    rules.push({id:`rule-${rules.length+1}`,sourceRef:p.sourceIp,destinationRef:p.destinationIp,scope:'host-host',protocol:p.protocol||'any',destinationPort:p.destinationPort??null,service:p.service??null,purpose:'Observed communication',allowed:!!p.confirmed,confirmed:!!p.confirmed,source:p.source||'legacy profile',confidence:p.confidence||'low',reason:p.reason||'Migrated observed communication.',observations:p.observations});
  }
  for(const h of ac.allowedHosts||[]) addRule('*',String(h),'host-host');
  for(const p of ac.allowedPairs||[]) addRule(String(p[0]),String(p[1]),'host-host');
  for(const p of ac.allowedSegmentPairs||[]) addRule(String(p[0]),String(p[1]),'segment-segment');
  for(const d of ac.approvedExternalDestinations||[]) addRule('*',String(d),'external');
  out.environment.communicationRules=rules;
  return out;
}

export function saveProfileLocal(profile: DetectionProfile): void { localStorage.setItem(KEY, JSON.stringify(profile)); }
export function loadProfileLocal(): DetectionProfile | null {
  const raw=localStorage.getItem(KEY) || localStorage.getItem(LEGACY_KEY);
  return raw ? migrateProfile(JSON.parse(raw)) : null;
}
export function exportProfile(profile: DetectionProfile): void {
  const blob = new Blob([JSON.stringify(profile, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${profile.profile.name.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').toLowerCase() || 'network-profile'}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
export async function importProfile(file: File): Promise<DetectionProfile> { return migrateProfile(JSON.parse(await file.text())); }
