# @talaljaber/vibesafe-attack

Attack Mode for [VibeSafe](https://github.com/Talaljaber/Vibesafe): confirms or refutes static
findings with a small number of safe live requests against a local dev server.

This package is a scaffold. The public API is declared but not implemented yet.

## Safety model

- Only `GET` requests, only to loopback hosts (plus an optional pinned Supabase project).
- All network I/O lives in `src/http/`. A lint rule and a structural test forbid network modules
  everywhere else in the package.
- No LLM calls.

## License

MIT
