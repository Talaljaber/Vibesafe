/**
 * Redacts a secret for safe display in reports and JSON output.
 * Leaves the first 4 and last 4 characters visible if the string is long enough.
 * If the string is too short, it aggressively masks it to prevent accidental exposure.
 */
export function redactSecret(secret: string): string {
  if (!secret) return secret;
  if (secret.length <= 4) {
    return "***";
  }
  if (secret.length <= 8) {
    return secret.substring(0, 2) + "***" + secret.substring(secret.length - 1);
  }
  
  return secret.substring(0, 4) + "..." + secret.substring(secret.length - 4);
}
