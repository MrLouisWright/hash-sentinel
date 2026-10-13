import type { Report, PolicyOptions, Severity } from './core.js';
export * from './core.js';
export type HashType = 'md5' | 'sha1' | 'sha256' | 'sha512';
export type OnlineSource = 'circl' | 'malwarebazaar' | 'virustotal';
export interface FeedEntry { hash: string; label?: string; malicious: boolean; meta?: Record<string, unknown>; }
export interface FeedSpec { path?: string; url?: string; name?: string; malicious?: boolean; format?: 'auto' | 'text' | 'csv' | 'json'; ttl?: number; }
export interface Match { feed: string; label?: string; malicious: boolean; hash: string; meta?: Record<string, unknown>; }
export interface LookupResult { source: OnlineSource; found: boolean; malicious?: boolean; knownGood?: boolean; label?: string; detail?: object; error?: string; skipped?: string; }
export interface CheckOptions extends PolicyOptions { feeds?: (string | FeedSpec)[]; knownGood?: (string | FeedSpec)[]; online?: OnlineSource[]; offline?: boolean; ttl?: number; cache?: string; endpoints?: Partial<Record<OnlineSource, string>>; keys?: Partial<Record<'malwarebazaar' | 'virustotal', string>>; fetchImpl?: typeof fetch; concurrency?: number; timeout?: number; }
export interface HashData { hashes: Partial<Record<HashType, string>>; status: 'malicious' | 'listed' | 'known-good' | 'unknown'; matches: Match[]; knownGood: Match[]; online: LookupResult[]; }
export declare class HashIndex { add(hash: string, entry: Omit<Match, 'hash'>): void; get(hash: string): Omit<Match, 'hash'>[]; readonly size: number; feeds: { name: string; entries: number; unique?: number; error?: string }[]; }
export declare const VERSION: string;
export declare const SOURCES: OnlineSource[];
export declare const ENDPOINTS: Record<OnlineSource, string>;
export declare const RULES: Record<string, { severity: Severity; title: string; group: string }>;
export declare function hashType(value: string): HashType | null;
export declare function hashFile(path: string): Promise<Record<HashType, string>>;
export declare function parseFeed(text: string, opts?: { name?: string; format?: 'auto' | 'text' | 'csv' | 'json'; malicious?: boolean }): FeedEntry[];
export declare function loadFeeds(feeds: (string | FeedSpec)[], opts?: { index?: HashIndex; cache?: string; ttl?: number; offline?: boolean; errors?: string[]; fetchImpl?: typeof fetch }): Promise<HashIndex>;
export declare function lookup(source: OnlineSource, hash: string, type: HashType, opts?: Pick<CheckOptions, 'endpoints' | 'keys' | 'fetchImpl' | 'timeout'>): Promise<LookupResult>;
export declare function check(inputs: string[], opts?: CheckOptions): Promise<Report<Record<string, unknown>, HashData>>;
export declare function formatTable(report: Report): string;
export declare function cacheDir(): string;
