import { isIP } from "node:net";

type IpFamily = 4 | 6;

interface ParsedIpRule {
  readonly family: IpFamily;
  readonly network: string;
  readonly prefix: number;
  readonly source: string;
}

function parseIPv4Parts(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return null;
  }

  const values = parts.map((part) => Number(part));
  if (values.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    return null;
  }

  return values;
}

function ipv4ToBigInt(ip: string): bigint | null {
  const parts = parseIPv4Parts(ip);
  if (!parts) {
    return null;
  }

  return (BigInt(parts[0]) << 24n) | (BigInt(parts[1]) << 16n) | (BigInt(parts[2]) << 8n) | BigInt(parts[3]);
}

function parseHexGroup(group: string): number | null {
  if (!group) {
    return null;
  }
  const value = Number.parseInt(group, 16);
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    return null;
  }
  return value;
}

function ipv6ToBigInt(ip: string): bigint | null {
  let value = ip;
  const zoneIndex = value.indexOf("%");
  if (zoneIndex >= 0) {
    value = value.slice(0, zoneIndex);
  }

  if (value.includes(".")) {
    const lastColon = value.lastIndexOf(":");
    if (lastColon < 0) {
      return null;
    }
    const ipv4Part = value.slice(lastColon + 1);
    const ipv4 = parseIPv4Parts(ipv4Part);
    if (!ipv4) {
      return null;
    }

    const hexPartA = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const hexPartB = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    value = `${value.slice(0, lastColon)}:${hexPartA}:${hexPartB}`;
  }

  const split = value.split("::");
  if (split.length > 2) {
    return null;
  }

  const left = split[0] ? split[0].split(":") : [];
  const right = split.length === 2 && split[1] ? split[1].split(":") : [];

  if (split.length === 1 && left.length !== 8) {
    return null;
  }

  const zerosToInsert = 8 - (left.length + right.length);
  if (zerosToInsert < 0) {
    return null;
  }
  if (split.length === 1 && zerosToInsert !== 0) {
    return null;
  }

  const groups = [...left, ...Array(zerosToInsert).fill("0"), ...right];
  if (groups.length !== 8) {
    return null;
  }

  const numeric = groups.map(parseHexGroup);
  if (numeric.some((group) => group == null)) {
    return null;
  }

  let output = 0n;
  for (const group of numeric as number[]) {
    output = (output << 16n) | BigInt(group);
  }
  return output;
}

function ipToBigInt(ip: string, family: IpFamily): bigint | null {
  return family === 4 ? ipv4ToBigInt(ip) : ipv6ToBigInt(ip);
}

function normalizeIpLiteral(rawValue: string): string | null {
  let value = rawValue.trim();
  if (!value) {
    return null;
  }

  if (value.includes(",")) {
    const [first] = value.split(",");
    value = (first ?? "").trim();
  }

  if (value.startsWith("[") && value.includes("]")) {
    value = value.slice(1, value.indexOf("]"));
  }

  const zoneIndex = value.indexOf("%");
  if (zoneIndex >= 0) {
    value = value.slice(0, zoneIndex);
  }

  if (value.startsWith("::ffff:")) {
    const mapped = value.slice("::ffff:".length);
    if (isIP(mapped) === 4) {
      return mapped;
    }
  }

  if (isIP(value) === 0 && value.includes(":")) {
    const [host, maybePort] = value.split(":");
    if (host && maybePort && isIP(host) === 4 && /^\d+$/.test(maybePort)) {
      value = host;
    }
  }

  return isIP(value) === 0 ? null : value;
}

function parseRule(rawRule: string): ParsedIpRule | null {
  const source = rawRule.trim();
  if (!source) {
    return null;
  }

  const [networkRaw, prefixRaw] = source.split("/");
  const network = normalizeIpLiteral(networkRaw ?? "");
  if (!network) {
    return null;
  }

  const family = isIP(network);
  if (family !== 4 && family !== 6) {
    return null;
  }

  if (prefixRaw == null) {
    return {
      family,
      network,
      prefix: family === 4 ? 32 : 128,
      source: network,
    };
  }

  if (!/^\d+$/.test(prefixRaw)) {
    return null;
  }

  const prefix = Number(prefixRaw);
  const maxBits = family === 4 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxBits) {
    return null;
  }

  return {
    family,
    network,
    prefix,
    source: `${network}/${prefix}`,
  };
}

function isInCidr(clientIp: string, rule: ParsedIpRule): boolean {
  const family = isIP(clientIp);
  if (family !== rule.family) {
    return false;
  }

  const maxBits = rule.family === 4 ? 32 : 128;
  const client = ipToBigInt(clientIp, rule.family);
  const network = ipToBigInt(rule.network, rule.family);
  if (client == null || network == null) {
    return false;
  }

  if (rule.prefix === 0) {
    return true;
  }

  const shift = BigInt(maxBits - rule.prefix);
  const fullMask = (1n << BigInt(maxBits)) - 1n;
  const hostMask = (1n << shift) - 1n;
  const networkMask = fullMask ^ hostMask;

  return (client & networkMask) === (network & networkMask);
}

export function normalizeAllowedIpRules(allowedIps: string[] | null | undefined): string[] {
  if (allowedIps == null) {
    return [];
  }

  if (!Array.isArray(allowedIps)) {
    throw new Error("allowedIps must be an array of IP/CIDR strings");
  }

  const dedup = new Set<string>();
  for (const value of allowedIps) {
    if (typeof value !== "string") {
      throw new Error("allowedIps entries must be strings");
    }
    const parsed = parseRule(value);
    if (!parsed) {
      throw new Error(`Invalid allowedIps entry '${value}'. Expected IP or CIDR (example: 195.7.8.9 or 195.7.8.0/24).`);
    }
    dedup.add(parsed.source);
  }

  return Array.from(dedup);
}

export function sanitizeAllowedIpRules(rawAllowedIps: unknown): string[] {
  if (!Array.isArray(rawAllowedIps)) {
    return [];
  }

  const dedup = new Set<string>();
  for (const rawValue of rawAllowedIps) {
    if (typeof rawValue !== "string") {
      continue;
    }
    const parsed = parseRule(rawValue);
    if (!parsed) {
      continue;
    }
    dedup.add(parsed.source);
  }

  return Array.from(dedup);
}

export function extractClientIp(...sources: unknown[]): string | null {
  const candidates: string[] = [];

  const pushSource = (source: unknown) => {
    if (typeof source === "string") {
      candidates.push(source);
      return;
    }
    if (Array.isArray(source)) {
      for (const value of source) {
        if (typeof value === "string") {
          candidates.push(value);
        }
      }
    }
  };

  for (const source of sources) {
    pushSource(source);
  }

  for (const candidate of candidates) {
    const normalized = normalizeIpLiteral(candidate);
    if (normalized) {
      return normalized;
    }
  }

  return null;
}

export function isClientIpAllowed(clientIp: string, allowedIps: string[]): boolean {
  if (allowedIps.length === 0) {
    return true;
  }

  const normalizedClientIp = normalizeIpLiteral(clientIp);
  if (!normalizedClientIp) {
    return false;
  }

  for (const rule of allowedIps) {
    const parsed = parseRule(rule);
    if (!parsed) {
      continue;
    }
    if (isInCidr(normalizedClientIp, parsed)) {
      return true;
    }
  }

  return false;
}
