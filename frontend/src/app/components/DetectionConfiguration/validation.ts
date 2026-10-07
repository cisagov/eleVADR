import { DetectionConfigurationProfile, ValidationIssue } from "./types";

export function isIpv4(value: string): boolean {
  const parts = value.trim().split(".");
  return (
    parts.length === 4 &&
    parts.every(
      (part) =>
        /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255,
    )
  );
}

export function isIpv6(value: string): boolean {
  const text = value.trim();
  return text.includes(":") && /^[0-9a-f:]+$/i.test(text) && text.length >= 2;
}

export function isIp(value: string): boolean {
  return isIpv4(value) || isIpv6(value);
}

export function isHostname(value: string): boolean {
  const text = value.trim();
  if (!text || text.length > 253) return false;
  return text
    .split(".")
    .every(
      (label) =>
        label.length > 0 &&
        label.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label),
    );
}

export function isIpOrHostname(value: string): boolean {
  return isIp(value) || isHostname(value);
}

export function isCidr(value: string): boolean {
  const [address, prefixRaw, extra] = value.trim().split("/");
  if (
    extra !== undefined ||
    prefixRaw === undefined ||
    !/^\d+$/.test(prefixRaw)
  )
    return false;
  const prefix = Number(prefixRaw);
  return (
    (isIpv4(address) && prefix >= 0 && prefix <= 32) ||
    (isIpv6(address) && prefix >= 0 && prefix <= 128)
  );
}

export function isDestination(value: string): boolean {
  const text = value.trim();
  return isIpOrHostname(text) || isCidr(text);
}

export function normalizeMac(value: string): string | undefined {
  const compact = value
    .trim()
    .toLowerCase()
    .replace(/[^0-9a-f]/g, "");
  if (!/^[0-9a-f]{12}$/.test(compact)) return undefined;
  return compact.match(/.{2}/g)?.join(":");
}
export function isMac(value: string): boolean {
  return Boolean(normalizeMac(value));
}

export function isValidPort(value: number | undefined): boolean {
  return (
    value === undefined ||
    (Number.isInteger(value) && value >= 1 && value <= 65535)
  );
}
export function isValidVlan(value: number | undefined): boolean {
  return (
    value === undefined ||
    (Number.isInteger(value) && value >= 0 && value <= 4095)
  );
}

function duplicates(values: string[]): Set<string> {
  const seen = new Set<string>();
  const duplicate = new Set<string>();
  values.forEach((raw) => {
    const value = raw.trim().toLowerCase();
    if (!value) return;
    if (seen.has(value)) duplicate.add(value);
    else seen.add(value);
  });
  return duplicate;
}

export function validateProfile(
  profile: DetectionConfigurationProfile,
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (!profile.name.trim())
    issues.push({
      path: "name",
      message: "Profile Name is required.",
      severity: "error",
    });

  const segmentKeys = duplicates(profile.segments.map((item) => item.cidr));
  profile.segments.forEach((item, index) => {
    if (!item.cidr.trim())
      issues.push({
        path: `segments.${item.id}.cidr`,
        message: "CIDR is required.",
        severity: "error",
      });
    else if (!isCidr(item.cidr))
      issues.push({
        path: `segments.${item.id}.cidr`,
        message: "Enter a valid IPv4 or IPv6 CIDR.",
        severity: "error",
      });
    if (!isValidVlan(item.vlanId))
      issues.push({
        path: `segments.${item.id}.vlanId`,
        message: "VLAN must be between 0 and 4095.",
        severity: "error",
      });
    if (segmentKeys.has(item.cidr.trim().toLowerCase()))
      issues.push({
        path: `segments.${item.id}.cidr`,
        message: "Duplicate network segment CIDR.",
        severity: "error",
      });
    if (!item.name.trim())
      issues.push({
        path: `segments.${item.id}.name`,
        message: `Segment ${index + 1} needs a name.`,
        severity: "warning",
      });
  });

  const assetKeys = duplicates(profile.assets.map((item) => item.ip));
  profile.assets.forEach((item) => {
    if (!item.ip.trim())
      issues.push({
        path: `assets.${item.id}.ip`,
        message: "IP address is required.",
        severity: "error",
      });
    else if (!isIp(item.ip))
      issues.push({
        path: `assets.${item.id}.ip`,
        message: "Enter a valid IPv4 or IPv6 address.",
        severity: "error",
      });
    if (assetKeys.has(item.ip.trim().toLowerCase()))
      issues.push({
        path: `assets.${item.id}.ip`,
        message: "Duplicate asset IP address.",
        severity: "error",
      });
    item.macAddresses.forEach((mac, i) => {
      if (!isMac(mac))
        issues.push({
          path: `assets.${item.id}.macAddresses.${i}`,
          message: "Enter a valid 48-bit MAC address.",
          severity: "error",
        });
    });
    if (duplicates(item.macAddresses).size)
      issues.push({
        path: `assets.${item.id}.macAddresses`,
        message: "Duplicate MAC address on this asset.",
        severity: "error",
      });
  });

  const infrastructureKeys = duplicates(
    profile.infrastructure.map((item) => `${item.kind}|${item.value}`),
  );
  profile.infrastructure.forEach((item) => {
    if (!item.value.trim())
      issues.push({
        path: `infrastructure.${item.id}.value`,
        message: "IP/host is required.",
        severity: "error",
      });
    else if (!isIpOrHostname(item.value))
      issues.push({
        path: `infrastructure.${item.id}.value`,
        message: "Enter a valid IP address or hostname.",
        severity: "error",
      });
    if (
      infrastructureKeys.has(`${item.kind}|${item.value}`.trim().toLowerCase())
    )
      issues.push({
        path: `infrastructure.${item.id}.value`,
        message: "Duplicate trusted infrastructure entry.",
        severity: "error",
      });
  });

  const pairKeys = duplicates(
    profile.communicationPairs.map(
      (item) =>
        `${item.sourceIp}|${item.destinationIp}|${item.protocol || ""}|${item.destinationPort ?? ""}|${item.service || ""}`,
    ),
  );
  profile.communicationPairs.forEach((item) => {
    if (!isIp(item.sourceIp))
      issues.push({
        path: `pairs.${item.id}.sourceIp`,
        message: "Enter a valid source IP address.",
        severity: "error",
      });
    if (!isIp(item.destinationIp))
      issues.push({
        path: `pairs.${item.id}.destinationIp`,
        message: "Enter a valid destination IP address.",
        severity: "error",
      });
    if (!isValidPort(item.destinationPort))
      issues.push({
        path: `pairs.${item.id}.destinationPort`,
        message: "Port must be between 1 and 65535.",
        severity: "error",
      });
    const key =
      `${item.sourceIp}|${item.destinationIp}|${item.protocol || ""}|${item.destinationPort ?? ""}|${item.service || ""}`
        .trim()
        .toLowerCase();
    if (pairKeys.has(key))
      issues.push({
        path: `pairs.${item.id}.duplicate`,
        message: "Duplicate communication pair.",
        severity: "error",
      });
  });

  const segmentNames = new Set(
    profile.segments
      .flatMap((x) => [
        x.name.trim().toLowerCase(),
        x.cidr.trim().toLowerCase(),
      ])
      .filter(Boolean),
  );
  const segmentPairKeys = duplicates(
    profile.allowedSegmentPairs.map(
      (x) => `${x.sourceSegment}|${x.destinationSegment}`,
    ),
  );
  profile.allowedSegmentPairs.forEach((item) => {
    if (!item.sourceSegment.trim())
      issues.push({
        path: `segmentPairs.${item.id}.sourceSegment`,
        message: "Source segment is required.",
        severity: "error",
      });
    if (!item.destinationSegment.trim())
      issues.push({
        path: `segmentPairs.${item.id}.destinationSegment`,
        message: "Destination segment is required.",
        severity: "error",
      });
    if (
      item.sourceSegment.trim() &&
      !segmentNames.has(item.sourceSegment.trim().toLowerCase())
    )
      issues.push({
        path: `segmentPairs.${item.id}.sourceSegment`,
        message:
          "Source segment does not match a configured segment name or CIDR.",
        severity: "warning",
      });
    if (
      item.destinationSegment.trim() &&
      !segmentNames.has(item.destinationSegment.trim().toLowerCase())
    )
      issues.push({
        path: `segmentPairs.${item.id}.destinationSegment`,
        message:
          "Destination segment does not match a configured segment name or CIDR.",
        severity: "warning",
      });
    if (
      segmentPairKeys.has(
        `${item.sourceSegment}|${item.destinationSegment}`.toLowerCase(),
      )
    )
      issues.push({
        path: `segmentPairs.${item.id}.duplicate`,
        message: "Duplicate segment communication exception.",
        severity: "error",
      });
  });

  const controlKeys = duplicates(
    profile.authorizedControlActions.map(
      (x) =>
        `${x.protocol}|${x.source}|${x.destination}|${x.allowedOperations.join(";")}|${x.allowedFunctionCodes.join(";")}`,
    ),
  );
  profile.authorizedControlActions.forEach((item) => {
    if (!isDestination(item.source))
      issues.push({
        path: `controlActions.${item.id}.source`,
        message: "Enter a valid source IP, hostname, or CIDR.",
        severity: "error",
      });
    if (!isDestination(item.destination))
      issues.push({
        path: `controlActions.${item.id}.destination`,
        message: "Enter a valid destination IP, hostname, or CIDR.",
        severity: "error",
      });
    if (!item.allowedOperations.length && !item.allowedFunctionCodes.length)
      issues.push({
        path: `controlActions.${item.id}.authorization`,
        message: "Specify at least one allowed operation or function code.",
        severity: "warning",
      });
    if (
      controlKeys.has(
        `${item.protocol}|${item.source}|${item.destination}|${item.allowedOperations.join(";")}|${item.allowedFunctionCodes.join(";")}`.toLowerCase(),
      )
    )
      issues.push({
        path: `controlActions.${item.id}.duplicate`,
        message: "Duplicate authorized control-action rule.",
        severity: "error",
      });
  });

  const ignoredKeys = duplicates(profile.allowedHosts);
  profile.allowedHosts.forEach((item, index) => {
    if (!isIpOrHostname(item))
      issues.push({
        path: `allowedHosts.${index}`,
        message: "Enter a valid IP address or hostname.",
        severity: "error",
      });
    if (ignoredKeys.has(item.trim().toLowerCase()))
      issues.push({
        path: `allowedHosts.${index}`,
        message: "Duplicate ignored host.",
        severity: "error",
      });
  });

  const destinationKeys = duplicates(profile.approvedExternalDestinations);
  profile.approvedExternalDestinations.forEach((item, index) => {
    if (!isDestination(item))
      issues.push({
        path: `externalDestinations.${index}`,
        message: "Enter a valid IP address, hostname, or CIDR.",
        severity: "error",
      });
    if (destinationKeys.has(item.trim().toLowerCase()))
      issues.push({
        path: `externalDestinations.${index}`,
        message: "Duplicate external destination.",
        severity: "error",
      });
  });
  return issues;
}

export function firstIssueFor(
  issues: ValidationIssue[],
  path: string,
): string | undefined {
  return issues.find(
    (issue) =>
      issue.severity === "error" &&
      (issue.path === path || issue.path.startsWith(`${path}.`)),
  )?.message;
}
