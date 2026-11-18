const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Same function as the CLI's confirmationCode: SHA-256 of the state string,
 * first 5 bytes, Crockford base32, formatted XXXX-XXXX.
 */
export const confirmationCode = async (state: string): Promise<string> => {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(state)),
  ).subarray(0, 5);
  let bits = 0n;
  for (const byte of digest) bits = (bits << 8n) | BigInt(byte);
  let out = "";
  for (let i = 7; i >= 0; i--) out += CROCKFORD[Number((bits >> BigInt(i * 5)) & 31n)];
  return `${out.slice(0, 4)}-${out.slice(4)}`;
};
