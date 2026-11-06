import type { DetectionModuleDetail } from "./moduleDetails";
import { ADVANCED_POLICY_SCHEMA_BY_MODULE } from "./advancedPolicySchema";
import { MODULE_HELP_NUMERIC_DEFAULTS } from "./moduleHelpDefaults";

export interface StandardizedModuleHelp {
  inputs: string[];
  detectionLogic: string;
  thresholds: string[];
  contextInfluence: string[];
  truePositiveExample: string;
  falsePositiveExamples: string[];
  validationSteps: string[];
}

const humanize = (value: string): string =>
  value.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());

const isThresholdField = (key: string): boolean =>
  /(?:minimum|min_|maximum|max_|window|seconds|ratio|multiplier|count|events|flows|targets|observations|threshold|bytes|interval)/i.test(
    key,
  );

const contextLabel = (key: string): string => {
  if (
    /allowed|authorized|approved|expected|trusted|ignored|managed|engineering|controller|ot_hosts|control_system_hosts|infrastructure/i.test(
      key,
    )
  ) {
    return `${humanize(key)} can authorize, trust, scope, or suppress matching behavior.`;
  }
  if (/report_|require_|enforce_|scope_|enable_|treat_/i.test(key)) {
    return `${humanize(key)} changes when or how the detector evaluates matching evidence.`;
  }
  if (
    /ports|services|protocols|function|codes|groups|segments|prefixes|communities|reason/i.test(
      key,
    )
  ) {
    return `${humanize(key)} changes which traffic or protocol values are in scope.`;
  }
  return `${humanize(key)} is an optional detector-specific policy input.`;
};

function exampleFor(id: string, description: string): string {
  if (/(write|control|program|firmware|stop|snmp)/i.test(id))
    return "An engineering or management host performs a control-changing operation that is outside the explicitly authorized source, destination, operation, or function-code scope.";
  if (
    /(drift|change|new_|disappearance|gone_silent|jitter|cadence|role_reversal)/i.test(
      id,
    )
  )
    return "Previously stable OT behavior changes after the baseline period in a way that matches the detector rule and is not covered by configured policy.";
  if (/(exposure|internet|public|outbound|external)/i.test(id))
    return "An OT asset communicates across a boundary or to a destination that the active Detection Context does not identify as expected or approved.";
  if (/(scan|recon|fan|discovery)/i.test(id))
    return "A host performs discovery or connection activity at a breadth or rate that exceeds the detector's expected pattern.";
  if (/(brute|credential|kerberos|ldap|smb)/i.test(id))
    return "Authentication or credential-related evidence matches the detector's suspicious pattern without an applicable trusted-host or exception policy.";
  return `Captured traffic contains the behavior described by this module: ${description.charAt(0).toLowerCase()}${description.slice(1)}`;
}

function falsePositivesFor(id: string): string[] {
  if (/(write|control|program|firmware|stop|snmp)/i.test(id))
    return [
      "Planned maintenance or commissioning that has not yet been represented in Control Authorization.",
      "Legitimate engineering tools using a broader source, destination, or function scope than the configured policy.",
    ];
  if (
    /(drift|change|new_|disappearance|gone_silent|jitter|cadence|role_reversal)/i.test(
      id,
    )
  )
    return [
      "Planned equipment replacement, failover, firmware changes, or production schedule changes after the learned baseline.",
      "A capture that starts or ends during an unusual operating period and therefore produces an unrepresentative baseline.",
    ];
  if (/(scan|recon|fan|discovery)/i.test(id))
    return [
      "Approved asset inventory, vulnerability assessment, or network-management discovery activity.",
      "Commissioning or troubleshooting that temporarily contacts many endpoints.",
    ];
  if (/(exposure|internet|public|outbound|external)/i.test(id))
    return [
      "Approved vendor, cloud, update, DNS, NTP, or remote-support destinations missing from the active Context.",
      "NAT, routing, or sensor placement that makes expected traffic appear external.",
    ];
  if (/(volume|burst|surge|broadcast|multicast)/i.test(id))
    return [
      "Backups, software distribution, discovery bursts, or recovery activity during maintenance windows.",
      "Short captures where normal bursts dominate the observed baseline.",
    ];
  return [
    "Known maintenance, commissioning, testing, or recovery activity not represented in the active Detection Context.",
    "Incomplete asset, infrastructure, or exception data that causes expected traffic to be interpreted without site policy.",
  ];
}

export function standardizedModuleHelp(
  detail: DetectionModuleDetail,
  readinessDetail: string,
): StandardizedModuleHelp {
  const schema = ADVANCED_POLICY_SCHEMA_BY_MODULE[detail.id];
  const fields = schema?.fields || [];
  const thresholdFields = fields.filter(
    (field) => field.type === "number" || isThresholdField(field.key),
  );
  const policyFields = fields.filter(
    (field) => !thresholdFields.includes(field),
  );

  const logs = [
    ...detail.requiredLogs.map((log) => `${log}.log (required)`),
    ...detail.requiredAnyLogs.map(
      (log) => `${log}.log (one of the accepted evidence sources)`,
    ),
  ];

  return {
    inputs: logs.length
      ? logs
      : [
          "Available Zeek protocol/service evidence; this detector does not require one fixed log type.",
        ],
    detectionLogic: detail.description,
    thresholds: thresholdFields.length
      ? thresholdFields.map((field) => {
          const defaultValue =
            MODULE_HELP_NUMERIC_DEFAULTS[detail.id]?.[field.key];
          return defaultValue === undefined
            ? `${humanize(field.key)} — detector-specific numeric setting. The implementation defines the effective default.`
            : `${humanize(field.key)} — default ${defaultValue}. This value is taken from the detector implementation.`;
        })
      : [
          "No user-tunable numeric threshold is exposed for this detector. Any fixed implementation thresholds remain part of the detector rule rather than Detection Context policy.",
        ],
    contextInfluence: [
      readinessDetail,
      ...(policyFields.length
        ? policyFields.map((field) => contextLabel(field.key))
        : [
            "No detector-specific override fields are exposed; shared Detection Context classification and evidence still affect interpretation where applicable.",
          ]),
    ],
    truePositiveExample: exampleFor(detail.id, detail.description),
    falsePositiveExamples: falsePositivesFor(detail.id),
    validationSteps: [
      "Confirm the cited Zeek evidence and endpoints match the activity described in the finding.",
      "Review the active Detection Context for asset identity, trusted infrastructure, exceptions, and authorization that should apply.",
      "Check whether maintenance, commissioning, failover, scanning, or other approved activity explains the observation.",
      "If the behavior is expected, update narrowly scoped Context policy rather than broadly suppressing the detector.",
    ],
  };
}
