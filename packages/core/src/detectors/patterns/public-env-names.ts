// Names of client-exposed environment variables (NEXT_PUBLIC_*, VITE_*, ...) that
// belong to a server-only credential even though they contain no "SECRET"/"PASSWORD".

const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_/;
/** Public by design: anon/publishable keys, site keys, client ids, DSNs. */
const PUBLIC_BY_DESIGN =
  /(?:^|_)(?:ANON|PUBLISHABLE|PUBLIC_KEY|SITE_KEY|CLIENT_ID|DSN)(?:_|$)|^PK_/;
const PROVIDER_TOKEN =
  /(?:^|_)(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|MISTRAL|COHERE|REPLICATE|DEEPSEEK|PERPLEXITY|TOGETHER|FIREWORKS|ELEVENLABS|HUGGINGFACE|HF|XAI|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO|GITHUB|GITLAB|SLACK|DISCORD|NOTION|AIRTABLE)(?:_|$)/;
const CREDENTIAL_SUFFIX = /_(?:API_?KEY|KEY|TOKEN|AUTH_TOKEN|ACCESS_TOKEN|SECRET)$/;
/** Client database endpoints that are public by design (Firebase web config databaseURL). */
const PUBLIC_DB_ENDPOINT = /(?:^|_)FIREBASE_(?:DATABASE|DB)_URL$/;
const DB_URL =
  /(?:^|_)(?:DATABASE|DB|POSTGRES|POSTGRESQL|PG|MYSQL|MONGO|MONGODB)_(?:URL|URI|CONNECTION_STRING)$/;
const ADMIN_KEY = /(?:^|_)(?:ADMIN_(?:API_)?KEY|MASTER_KEY|SERVICE_KEY)$/;

/**
 * True when a public-prefixed variable name denotes a credential that must stay on the
 * server: provider API keys/tokens, database connection strings, admin/master keys, or
 * any service-role key. Anon/publishable/site keys, client ids and DSNs are public.
 */
export function isServerOnlyPublicName(name: string): boolean {
  const upper = name.toUpperCase();
  if (!PUBLIC_PREFIX.test(upper)) return false;
  const rest = upper.replace(PUBLIC_PREFIX, "");
  if (rest.includes("SERVICE_ROLE")) return true;
  if (PUBLIC_BY_DESIGN.test(rest)) return false;
  if (PROVIDER_TOKEN.test(rest) && CREDENTIAL_SUFFIX.test(rest)) return true;
  if (PUBLIC_DB_ENDPOINT.test(rest)) return false;
  if (DB_URL.test(rest)) return true;
  return ADMIN_KEY.test(rest);
}
