# Security policy

Report vulnerabilities privately to the repository maintainers. Do not open public issues containing user clip data, tokens, device keys, recovery material, or reproduction steps that expose secrets.

Contract changes must preserve these invariants:

1. The backend stores ciphertext, authenticated metadata, and optional privacy-mode search artifacts—not plaintext clips.
2. A six-digit PIN is an unlock factor for a wrapped random master key, never the master key itself.
3. Biometric and voice systems produce local or 3FA attestations; raw biometric material is not synchronized through ClipTown.
4. Every sync mutation is idempotent and scoped to the authenticated user and registered device.
