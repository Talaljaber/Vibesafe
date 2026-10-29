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

/**
 * Generic validation middleware in a middleware position of the chain: a call
 * `validate(...)` / `validateBody(...)` or a bare identifier that is a whole argument.
 * Case-sensitive; matched per top-level argument, never against the handler body.
 */
export const EXPRESS_VALIDATE_MIDDLEWARE_CALL_REGEX =
  /^\s*validate(?:Body|Request|Query|Params|Schema|Input)?\s*\(/;
export const EXPRESS_VALIDATE_MIDDLEWARE_IDENT_REGEX =
  /^\s*validate(?:Body|Request|Query|Params|Schema|Input)?\s*$/;

/** Reads of the request body inside an Express handler. */
export const EXPRESS_BODY_READ_REGEX = /\b(?:req|request)\.body\b/;

/** Reads of query string / route params (only checked on mutating routes). */
export const EXPRESS_QUERY_READ_REGEX = /\b(?:req|request)\.(?:query|params)\b/;

/** `request.formData()` read (multipart upload). */
export const FORM_DATA_READ_REGEX = /\b(?:req|request)\.formData\s*\(/;

/** Request input other than form data: JSON/text bodies, query strings, search params. */
export const OTHER_INPUT_READ_REGEX =
  /\b(?:req|request)\.(?:json|text|arrayBuffer)\s*\(|\breq\.(?:body|query)\b|\bsearchParams\b/;

/** The uploaded value is checked to be a file: `x instanceof File` / `Blob`. */
export const FILE_INSTANCE_CHECK_REGEX = /\binstanceof\s+(?:File|Blob)\b/;

/** The upload's size is compared against a limit (`file.size > MAX`). */
export const FILE_SIZE_CHECK_REGEX = /\.size\s*[<>]=?|[<>]=?\s*[\w$.]*\.size\b/;

/** The upload's MIME type is checked (`file.type` compared or looked up in an allowlist). */
export const FILE_TYPE_CHECK_REGEX =
  /\.type\s*(?:[!=]==?|\))|\[\s*[\w$]+\.type\s*\]|\.(?:includes|has)\s*\(\s*[\w$]+\.type\s*\)/;

/** Reads of untrusted request input (body, text, form data, query string). */
export const INPUT_READ_REGEXES: RegExp[] = [
  /\b(?:req|request)\.(?:json|text|formData|arrayBuffer)\s*\(/,
  /\breq\.(?:body|query)\b/,
  /\bsearchParams\b/,
];
