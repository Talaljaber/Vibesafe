/** Import / require / dynamic import of a known validation library. */
export const VALIDATION_LIB_IMPORT_REGEX =
  /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)["'](?:zod|yup|joi|@hapi\/joi|valibot|superstruct|io-ts|class-validator|arktype|ajv|@sinclair\/typebox)(?:\/[^"']*)?["']/;

/**
 * Validation-style calls. `.parse(` on well-known non-schema receivers
 * (JSON, path, url, ...) does not count.
 */
export const VALIDATION_CALL_REGEXES: RegExp[] = [
  /(?<!\b(?:JSON|path|url|Url|qs|querystring|Date|yaml|toml|csv|marked))\.(?:safeParse|parse)(?:Async)?\s*\(/,
  /\.validate(?:Sync|Async)?\s*\(/,
  /\bvalidateOrReject\s*\(/,
];

/** Function-style validation (superstruct `assert(x, S)`, io-ts `decode(`); only counted when a validation library is imported. */
export const VALIDATION_LIB_CALL_REGEX = /\b(?:assert|create|decode|validate)\s*\(/;

/** Reads of untrusted request input (body, text, form data, query string). */
export const INPUT_READ_REGEXES: RegExp[] = [
  /\b(?:req|request)\.(?:json|text|formData|arrayBuffer)\s*\(/,
  /\breq\.(?:body|query)\b/,
  /\bsearchParams\b/,
];
