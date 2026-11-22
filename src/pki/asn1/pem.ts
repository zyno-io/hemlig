export class PemError extends Error {
  public constructor(
    public readonly reason:
      "no_block" | "multiple_blocks" | "malformed" | "too_large",
  ) {
    super(`Invalid PEM (${reason}).`);
  }
}

export const toPem = (der: Uint8Array, label: string): string => {
  const body =
    Buffer.from(der)
      .toString("base64")
      .match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${body.join("\n")}\n-----END ${label}-----\n`;
};

/**
 * Decodes text holding exactly one PEM block of `label` and nothing else. The base64 body must be canonical, so one
 * DER encoding has one accepted PEM spelling modulo line breaks.
 */
export const fromPem = (
  text: string,
  label: string,
  maxBytes = 32_768,
): Buffer => {
  if (Buffer.byteLength(text, "utf8") > maxBytes) {
    throw new PemError("too_large");
  }
  const begins = text.match(/-----BEGIN /g)?.length ?? 0;
  if (begins === 0) {
    throw new PemError("no_block");
  }
  if (begins > 1) {
    throw new PemError("multiple_blocks");
  }
  const match = new RegExp(
    `^\\s*-----BEGIN ${label}-----\\r?\\n([A-Za-z0-9+/=\\r\\n]+)-----END ${label}-----\\s*$`,
  ).exec(text);
  if (match?.[1] === undefined) {
    throw new PemError("malformed");
  }
  const base64 = match[1].replace(/[\r\n]/g, "");
  const der = Buffer.from(base64, "base64");
  if (der.length === 0 || der.toString("base64") !== base64) {
    throw new PemError("malformed");
  }
  return der;
};
