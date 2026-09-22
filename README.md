# Browser Vault

Browser Vault is a client-side encrypted file vault. The browser generates and uses file keys with Web Crypto; the server stores ciphertext and metadata only.

## Security model

- Files are encrypted in the browser with AES-GCM before upload. Large files use 4 MiB encrypted chunks with per-chunk nonces.
- The server never receives plaintext files, user passwords, private keys, or file keys. It stores encrypted key packages and encrypted private-key material.
- Password handling uses browser-side PBKDF2 derivation. The server stores only an authentication verifier.
- User RSA-OAEP public keys are stored as the foundation for administrator key wrapping.
- Each file key is wrapped for the current user and for every administrator public key returned by the server.
- Password changes re-wrap the same user key and the encrypted private key after the old password unlocks them, so existing files keep working.
- The administrator browser workflow for opening administrator key packages is still the next module.

The server can still alter the JavaScript it serves. Production use requires HTTPS, a trusted deployment pipeline, a strict Content Security Policy, and a way to verify the frontend bundle.

## Run

```bash
go run .
```

Open <http://127.0.0.1:8080>.

The default encrypted upload limit is 200 MiB. Set `BROWSER_VAULT_ADDR` to change the listen address and `BROWSER_VAULT_DATA_DIR` to choose the data directory.
