# firebase-app corpus

Neutral Firebase rules used by `registry-integrity.test.ts` so the Firebase rules detector runs
on real files (discovery through `firebase.json`, Firestore, Storage and Realtime Database
formats). The open catch-all, signed-in storage root and RTDB test-mode read are deliberate;
the scoped rules next to them must stay silent.
