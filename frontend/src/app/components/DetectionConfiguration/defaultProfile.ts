import {ALL_MODULE_IDS} from './moduleCatalog';
import type {DetectionProfile} from './types';

export function createEmptyProfile(name = 'New Network Profile'): DetectionProfile {
  const now = new Date().toISOString();
  return {
    schemaVersion: 2,
    profile: {name, description: '', createdAt: now, updatedAt: now},
    selectedModules: [...ALL_MODULE_IDS],
    discovery: {scannedAt: '', files: [], logTypes: [], captureStart: null, captureEnd: null, observedHosts: 0, observedPairs: 0, warnings: []},
    environment: {
      segments: [],
      assets: [],
      communicationRules: [],
      protocolAuthorizations: [],
      observedVlanIds: [],
      observedInnerVlanIds: [],
      observedServices: [],
    },
    detectionTuning: {
      mode: 'recommended',
      baselineSeconds: 3600,
      minimumObservations: 4,
      timingTolerance: 0.25,
      minimumEventCount: 5,
    },
    modulePolicies: Object.fromEntries(ALL_MODULE_IDS.map(id => [id, {}])),
    readiness: [],
  };
}
