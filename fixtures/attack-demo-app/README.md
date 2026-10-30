# attack-demo-app

Deliberately vulnerable demo for VibeSafe Attack Mode. Local only. In-memory store with a Supabase-shaped query API.

Do not fix this directory: it is a test fixture. `../attack-demo-app-fixed/` is an overlay holding only the files that change in the fixed version. Run `node server.mjs [--port <n|0>] [--overlay <dir>]` to serve it on 127.0.0.1 without installing anything.
