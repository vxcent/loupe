# Audit Playbook (v1)

## General
- Interact only through tools; verify each step against the OBSERVATION before
  moving on. Only submit a flag you actually obtained from a tool.

## Crypto: XOR / Stream-Cipher Weakness
- **Budget**: If a brute-force search over a small key space (e.g., single byte,
  0–255) is possible, try up to 256 candidates before concluding. Do not stop
  early unless a valid plaintext format is confirmed.
- **Pattern recognition**: When a ciphertext appears to be XORed with a repeating
  short key, and you can see partial structure in decrypted attempts (e.g.,
  printable ASCII, but with consistent offsets), use a known-plaintext crib or
  frequency analysis instead of blind exhaustive search.
- **Validation**: Before submitting, check that the decrypted output matches the
  expected flag format (e.g., `flag{...}` or similar) and contains only
  printable characters. If not, the key is wrong; continue searching.
- **Efficiency tactic**: If the key is a single byte, compute the XOR of the
  ciphertext with the crib `flag{` at each offset to recover the key byte
  directly, then decrypt and validate. This avoids iterating through the entire
  key space.