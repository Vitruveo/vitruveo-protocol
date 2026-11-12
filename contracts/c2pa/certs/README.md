# Vitruveo Content Credentials certificates

- `vitruveo-c2pa-root.pem` / `.der`: Vitruveo Content Credentials Root CA (P-256, valid to 2046-11). Trust anchor for the C2PA precompile (0x...CA).
  - Fingerprint (SHA-256 of DER), as used by `isAnchor`:
    `0x66e2bfd431681a9a42d5f8a4a06e7656006bc383db81b7f7d435e49a38c5ab49`
- `vitruveo-c2pa-signer.pem`: Vitruveo Content Credentials Signer (P-256, ES256, valid to 2029-11), issued by the root. EKU: emailProtection, documentSigning.

Private keys are not in this repo. They are in `~/Developer/Vitruveo/c2pa-ca/` (`root.key`, `signer.key`); keep the root key offline.

Sign with c2patool: `"alg": "es256", "private_key": "<signer.key>", "sign_cert": "<signer.pem>"`.
