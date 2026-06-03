/**
 * Default values shared by the HTTP store factory and its consumers.
 * Centralized so every code path that reads a default reads the same number.
 */
export const DEFAULT_MAX_SKEW_MS = 5 * 60 * 1000;
export const DEFAULT_SECRET_LENGTH_BYTES = 32;
export const DEFAULT_DB_SEED_BACKUP_TTL_SECONDS = 600;

/**
 * v1.4.0 (security): the federation-default clientId for the bootstrap-window
 * lock. Consumers who omit `requireBootstrapClientId` resolve to this exact
 * value so a fresh install joins the federation safely out of the box.
 * Overriding the option is supported for the rare case of an intentionally
 * isolated store. Cross-language ports (Python, Go, Rust, ...) reuse the
 * same byte sequence as the canonical wire value.
 */
export const DEFAULT_PROPAGATION_KEY_CLIENT_ID = "self_propagation_signer";
