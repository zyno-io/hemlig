import { EzError } from "./ez-error";
import type { EzKeyAlgorithm } from "./ez-x509";

/** Defaults and limits of the EZ profile (design sections 0, 2.2 and 7.3). */
export const EZ_DEFAULTS = {
  keyAlgorithm: "ECDSA_P384" as EzKeyAlgorithm,
  /** A new root lives 20 years. */
  rootValidityDays: 7300,
  intermediateValidityDays: 730,
  crlValidityDays: 180,
  /** The CRL is renewed when fewer days than this remain (the server alarms at 30). */
  crlRenewBeforeDays: 45,
  crlValidityMinDays: 60,
  crlValidityMaxDays: 400,
  /** Adopted roots must have at least this long left. */
  adoptMinimumRemainingDays: 90,
  /** Floor for an issued intermediate's remaining validity after clamping to the root. */
  intermediateMinimumDays: 90,
  /** Certificates are backdated by this much. */
  backdateMs: 3_600_000,
  /** Largest tolerated skew between this machine and the server. */
  clockSkewSeconds: 120,
  /** A CRL's thisUpdate may run at most this far ahead of the clock. */
  thisUpdateAheadSeconds: 300,
  slot: "9c",
  pinPolicy: "always" as const,
  touchPolicy: "always" as const,
} as const;

/** `730d`, `20y` (365-day years) or a bare number of days. Returns whole days. */
export const parseDuration = (text: string): number => {
  const match = /^(\d+)([dy]?)$/.exec(text.trim());
  const count = match === null ? 0 : Number(match[1]);
  if (match === null || !Number.isSafeInteger(count) || count < 1) {
    throw new EzError(2, "invalid_input", `Invalid duration "${text}"; use a number of days such as 730d, or years such as 20y.`);
  }
  return match[2] === "y" ? count * 365 : count;
};

/** Validates a CRL validity in days against the profile range. */
export const assertCrlValidityDays = (days: number): number => {
  if (days < EZ_DEFAULTS.crlValidityMinDays || days > EZ_DEFAULTS.crlValidityMaxDays) {
    throw new EzError(
      2,
      "invalid_input",
      `The CRL validity must be between ${EZ_DEFAULTS.crlValidityMinDays} and ${EZ_DEFAULTS.crlValidityMaxDays} days.`,
    );
  }
  return days;
};

/** Slots EZ may use. 9e (PIN never checked) and f9 (attestation) are refused. */
export const isAllowedSlot = (slot: string): boolean =>
  /^(9a|9c|9d|8[2-9a-f]|9[0-5])$/i.test(slot) && !/^9e$/i.test(slot);
