/**
 * Masking Strategies
 *
 * Pure functions that transform a secret value string into its masked form.
 * None of these functions ever log, store, or return the original value.
 *
 * FULL_MASK    → ********  (fixed 8-char mask by default)
 * FIXED_MASK   → *****     (exactly 5 stars, regardless of length)
 * PLACEHOLDER  → [CATEGORY_N]  (consistent within a session via a counter map)
 * PARTIAL_MASK → sk-****1234  (preserve leading/trailing chars)
 */

import type { MaskingOptions, MaskingStrategy } from '../../types/redaction'
import type { SecretCategory } from '../../types/detection'

export type PlaceholderCounter = Map<SecretCategory, number>

export function createPlaceholderCounter(): PlaceholderCounter {
  return new Map()
}

/**
 * Map from original secret value to its assigned placeholder label.
 * This ensures repeated occurrences of the same secret get the same label.
 */
export type PlaceholderValueMap = Map<string, string>

export function createPlaceholderValueMap(): PlaceholderValueMap {
  return new Map()
}

// ── strategy implementations ──────────────────────────────────────────────────

export function applyFullMask(options: MaskingOptions): string {
  const len = options.fullMaskLength ?? 8
  const ch = options.maskChar ?? '*'
  return ch.repeat(len)
}

export function applyFixedMask(options: MaskingOptions): string {
  const ch = options.maskChar ?? '*'
  return ch.repeat(5)
}

export function applyPlaceholder(
  value: string,
  category: SecretCategory,
  counter: PlaceholderCounter,
  valueMap: PlaceholderValueMap,
): string {
  // Return the same placeholder if this exact value was seen before
  const existing = valueMap.get(value)
  if (existing) return existing

  const count = (counter.get(category) ?? 0) + 1
  counter.set(category, count)

  const label = `[${categoryLabel(category)}_${count}]`
  valueMap.set(value, label)
  return label
}

export function applyPartialMask(value: string, options: MaskingOptions): string {
  const lead = options.leadingChars ?? 2
  const trail = options.trailingChars ?? 4
  const ch = options.maskChar ?? '*'

  if (value.length <= lead + trail) {
    // Value too short to partial-mask meaningfully — full-mask it
    return applyFullMask(options)
  }

  const maskLength = Math.max(4, value.length - lead - trail)
  return value.slice(0, lead) + ch.repeat(maskLength) + value.slice(value.length - trail)
}

/**
 * Categories whose characters must never be revealed, even partially:
 * a few characters of a password or key materially weaken it.
 */
const NEVER_PARTIAL: ReadonlySet<SecretCategory> = new Set<SecretCategory>([
  'PASSWORD',
  'PRIVATE_KEY',
  'BASIC_AUTH',
  'USERNAME',
  'CONNECTION_STRING',
])

/** Values shorter than this are always fully masked under PARTIAL_MASK. */
export const PARTIAL_MIN_LENGTH = 16

/**
 * PARTIAL_MASK with a safety policy: only long token-like values are partially
 * shown, and never more than one third of the value.
 */
export function applySafePartialMask(
  value: string,
  category: SecretCategory,
  options: MaskingOptions,
): string {
  if (NEVER_PARTIAL.has(category) || value.length < PARTIAL_MIN_LENGTH) {
    return applyFullMask(options)
  }
  const budget = Math.floor(value.length / 3)
  const trail = Math.min(options.trailingChars ?? 4, budget)
  const lead = Math.min(options.leadingChars ?? 2, budget - trail)
  return applyPartialMask(value, { ...options, leadingChars: lead, trailingChars: trail })
}

// ── dispatcher ────────────────────────────────────────────────────────────────

export interface MaskContext {
  options: MaskingOptions
  counter: PlaceholderCounter
  valueMap: PlaceholderValueMap
}

/**
 * Apply the configured strategy to a single secret value.
 * `strategyOverride` (from a custom rule) takes precedence over the global one.
 * Returns the replacement string; never throws.
 */
export function maskValue(
  value: string,
  category: SecretCategory,
  ctx: MaskContext,
  strategyOverride?: MaskingStrategy,
): string {
  if (!value) return applyFullMask(ctx.options)

  switch (strategyOverride ?? ctx.options.strategy) {
    case 'FULL_MASK':
      return applyFullMask(ctx.options)

    case 'FIXED_MASK':
      return applyFixedMask(ctx.options)

    case 'PLACEHOLDER':
      return applyPlaceholder(value, category, ctx.counter, ctx.valueMap)

    case 'PARTIAL_MASK':
      return applySafePartialMask(value, category, ctx.options)

    default:
      return applyFullMask(ctx.options)
  }
}

// ── helpers ───────────────────────────────────────────────────────────────────

function categoryLabel(category: SecretCategory): string {
  const labels: Record<SecretCategory, string> = {
    PASSWORD: 'PASSWORD',
    USERNAME: 'USERNAME',
    API_KEY: 'API_KEY',
    TOKEN: 'TOKEN',
    CONNECTION_STRING: 'CREDENTIAL',
    PRIVATE_KEY: 'PRIVATE_KEY',
    BEARER_TOKEN: 'BEARER_TOKEN',
    BASIC_AUTH: 'BASIC_AUTH',
    AWS_CREDENTIAL: 'AWS_CREDENTIAL',
    GITHUB_TOKEN: 'GITHUB_TOKEN',
    JWT: 'JWT',
    OAUTH_SECRET: 'OAUTH_SECRET',
    GENERIC_SECRET: 'SECRET',
    CUSTOM: 'SECRET',
  }
  return labels[category] ?? 'SECRET'
}
