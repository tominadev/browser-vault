# Browser Vault

Browser Vault is a client-side encrypted file vault. The browser generates and uses file keys with Web Crypto; the server stores ciphertext and metadata only.

## Security model

- Files are encrypted in the browser with AES-GCM before upload.
- The server never receives plaintext files, user passwords, private keys, or file keys.
- Password handling uses browser-side PBKDF2 derivation. The server stores only an authentication verifier.
- User RSA-OAEP public keys are stored as the foundation for administrator key wrapping.
- The current initial version implements browser-side file encryption and encrypted file-key packages; multi-administrator key ceremonies are the next module.
- Password changes will re-wrap the same user key after the old password unlocks it.

The server can still alter the JavaScript it serves. Production use requires HTTPS, a trusted deployment pipeline, a strict Content Security Policy, and a way to verify the frontend bundle.

## Run

```bash
go run .
```

Open <http://127.0.0.1:8080>.
