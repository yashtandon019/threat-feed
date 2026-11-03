export interface Env {
  DB: D1Database;
  ANTHROPIC_API_KEY?: string;
  INGEST_TOKEN?: string;
  SUMMARY_MODEL: string;
  SITE_URL: string;
}

export const KINDS = ['exploited_vuln', 'malicious_package', 'compromised_package', 'poisoned_action'] as const;
export type Kind = (typeof KINDS)[number];
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface OsvRange {
  type: string;
  events: Record<string, string>[];
}

export interface Affected {
  ecosystem: string;
  package: string;
  ranges: OsvRange[];
  versions: string[];
}

/** What every adapter emits. Stored as-is in source_records.record_json. */
export interface SourceRecord {
  source: string;
  sourceId: string;
  aliases: string[];
  kind: Kind;
  title: string;
  details: string;
  severity: Severity;
  affected: Affected[];
  url: string;
  published: string;
  withdrawn?: boolean;
  kev?: { dateAdded: string; dueDate: string; ransomware: boolean; requiredAction: string };
  epss?: number;
  /** Drop the record if no package could be linked (EPSS-only CVEs). */
  needsPackage?: boolean;
}

export interface Adapter {
  name: string;
  run(env: Env, cursor: string | null, now: Date): Promise<{ records: SourceRecord[]; cursor: string | null }>;
}

/** Tracked package ecosystems, using OSV's names. */
export const ECOSYSTEMS = ['npm', 'PyPI', 'Go', 'crates.io', 'Maven', 'NuGet', 'RubyGems', 'Packagist', 'GitHub Actions'];

export function normalizeEcosystem(s: string): string | undefined {
  const k = s.trim().toLowerCase();
  if (k === 'actions' || k === 'github-actions') return 'GitHub Actions';
  return ECOSYSTEMS.find((e) => e.toLowerCase() === k);
}
