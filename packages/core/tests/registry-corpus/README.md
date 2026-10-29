# Registry corpus

Small, deliberately insecure sample projects. `tests/scanner/registry-integrity.test.ts`
runs every registered detector on each top-level directory here (plus
`fixtures/nextjs-vibecoded-bad-app`) and checks every finding: ruleId literals, the
severity rubric, one category per detector and stable ids.

Each stream adds its own directory (for example `injection-app/`) with realistic samples
that make its new rules fire, so the integrity checks cover them. Paths are relative to
the sample directory, so test-path exclusions do not apply. Never put real-looking
provider tokens here (push protection); the fixture app covers secret patterns. Do not
"fix" the samples.
