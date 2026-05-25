/**
 * Default values shared by the HTTP store factory and its consumers.
 * Centralized so every code path that reads a default reads the same number.
 */
export const DEFAULT_MAX_SKEW_MS = 5 * 60 * 1000;
export const DEFAULT_SECRET_LENGTH_BYTES = 32;
export const DEFAULT_DB_SEED_BACKUP_TTL_SECONDS = 600;
