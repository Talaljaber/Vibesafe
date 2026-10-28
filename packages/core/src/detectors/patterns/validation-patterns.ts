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

/** Import / require of express-validator, celebrate or similar Express validation middleware. */
export const EXPRESS_VALIDATOR_IMPORT_REGEX =
  /(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)["'](?:express-validator|celebrate|express-joi-validation|zod-express-middleware)(?:\/[^"']*)?["']/;

/** Calls from express-validator / celebrate; only counted when the library is imported. */
export const EXPRESS_VALIDATOR_CALL_REGEX =
  /\b(?:body|check|query|param|cookie|header|oneOf|checkSchema|matchedData|validationResult|celebrate)\s*\(/;

/** Generic validation middleware, e.g. `validate(schema)`, `validateBody(schema)`, `validateRequest`. */
export const EXPRESS_VALIDATE_MIDDLEWARE_REGEX = /\bvalidat\w*\s*\(|\bvalidat(?:e|ion)\w*\s*(?=[,\])])/i;

/** Reads of untrusted request input inside an Express handler. */
export const EXPRESS_INPUT_READ_REGEX = /\b(?:req|request)\.(?:body|query|params)\b/;

/** Reads of untrusted request input (body, text, form data, query string). */
export const INPUT_READ_REGEXES: RegExp[] = [
  /\b(?:req|request)\.(?:json|text|formData|arrayBuffer)\s*\(/,
  /\breq\.(?:body|query)\b/,
  /\bsearchParams\b/,
];
