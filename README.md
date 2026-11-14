# 🔓 EHI-Unlocker

A single-file, **read-only** decoder for HTTP Injector `.ehi` configuration files
(`com.evozi.injector`. It peels back all thirteen layers of
the export format and hands you plain JSON. 🧅

Your original `.ehi` files are opened read-only and **never modified**. ✅

---

## ✨ What it does

`ehi_decode.py` walks the full export pipeline, failing loudly and precisely at
whichever stage breaks:

| # | Stage | What happens |
|---|-------|--------------|
| 0 | 📦 Header | Big-endian envelope: magic `ehi`, format version, app version, timestamp, payload length |
| 1 | 🔑 Key | SHA-256 of `Base64(SHA-1(signing cert))` |
| 2 | 🔐 Outer AES | AES-256-CBC/PKCS7, IV auto-selected from four known variants |
| 3 | ✂️ Split | `iv : mac : ciphertext`, Base64 |
| 4 | 🧪 PBKDF2 | PBKDF2-HMAC-SHA1, 5000 iterations → 384 bits |
| 5 | 🛡️ HMAC | HMAC-SHA256 integrity check |
| 6 | 🔐 Inner AES | AES-128-CBC/PKCS7 |
| 7 | 🧩 XXTEA | XXTEA decrypt + length unframe |
| 8 | 📄 ConfigShell | JSON envelope, real fields separated from decoys |
| 9 | 🔁 Il0 | Reverse → custom-alphabet Base64 → hex → XOR |
| 10 | 📬 Container | 10-byte header + 16-byte salt + 24-byte nonce + ciphertext |
| 11 | 🧮 Argon2id + AEAD | Argon2id (t=5, m=64 MiB, p=4) → XChaCha20-Poly1305 |
| 12 | 📄 Profile | The actual app configuration, as JSON |
| 13 | 🏷️ Fields | Per-field decode (`Il0`, `base64+XOR`, or plain) |

### 🎭 Decoy handling

The app injects fake fields whose names are two real field names glued together.
The decoder tests membership against the **declared field lists** rather than
guessing from the shape of a value, and keeps anything suspicious in separate
`shellDecoys` / `profileDecoys` buckets instead of throwing it away. 🗂️

---

## 📋 Requirements

- 🐍 Python 3 (developed and tested on 3.14)
- 📦 `cryptography` >= 44 — needs the `Argon2id` KDF
- 📦 `pynacl` — for XChaCha20-Poly1305

```bash
pip install cryptography pynacl
```

If either is missing, the script tells you exactly what to install and exits with
code `3`. `--help` and `--version` still work without them. 👍

---

## 🚀 Usage

Running it bare prints the help page:

```bash
python3 ehi_decode.py
```

Decode one or more files:

```bash
python3 ehi_decode.py config.ehi
python3 ehi_decode.py a.ehi b.ehi
```

### 🎛️ Options

| Flag | Meaning |
|------|---------|
| `--apk PATH` | APK or `.apks` bundle to read the signing certificate from |
| `--fp B64` | Supply `Base64(SHA-1(cert))` directly instead of an APK |
| `--outdir DIR` | Where to write the JSON (default: `decoded_full`) |
| `-v`, `--verbose` | Show the per-stage log and the container header |
| `-q`, `--quiet` | No human-readable dump, just write the JSON |
| `--json` | Emit result JSON on stdout (progress goes to stderr) |
| `--version` | Print the version |

### 🧾 The fingerprint, explained

The APK is only ever used to recover **one string**: `Base64(SHA-1(signing cert))`.
That value is a constant for any given build, so a built-in default is baked in and
the APK is entirely optional. 🎉

A wrong fingerprint can never produce bad output — it fails the outer AES unwrap or
the stage-5 HMAC, loudly. 🚫

### 🔗 Piping

```bash
python3 ehi_decode.py --json config.ehi | jq '.profile.host'
```

`--json` keeps stdout pure JSON, so it pipes cleanly into `jq`. 🪠

---

## 📤 Output

For each input file, `<outdir>/<name>.json` containing:

| Key | Contents |
|-----|----------|
| `envelope` | Parsed file header |
| `shell` | Real `ConfigShell` envelope fields |
| `shellDecoys` | Non-declared shell keys |
| `profile` | The decoded configuration 🎯 |
| `profileDecoys` | Injected fake fields |
| `profileFieldEncoding` | How each field was stored (`Il0` / `plain` / `raw`) |

Plus `<outdir>/report.json` — a per-file, per-stage log of what succeeded or failed. 📝

---

## 🚦 Exit codes

| Code | Meaning |
|------|---------|
| `0` | ✅ Success |
| `1` | ❌ At least one file failed to decode |
| `2` | ⚠️ Usage error (includes a bare run with no input) |
| `3` | 📦 A required dependency is missing |
| `130` | 🛑 Interrupted (Ctrl-C) |

In a batch, one bad file does not stop the others — each is reported
individually and the exit code reflects the worst outcome. 🔄

---

## ⚠️ Limitations

- 🎯 Targets the **6.5.0** export format. Other versions may well differ.
- 🚧 **Decode only.** Despite the repository name, there is no re-encoder or
  lock-stripper yet — nothing here writes an `.ehi` file.
- 🧪 Verified end-to-end against a **synthetic** test vector built by inverting all
  thirteen stages. No real-world `.ehi` sample is included in this repository.
- 🧼 The source is deliberately free of comments and docstrings. All explanation
  lives in this README and in `--help`.

---

## 🙏 Responsible use

Intended for inspecting configurations you own or are authorised to analyse —
interoperability, debugging, and understanding what a config actually does to your
traffic. Please respect the terms of any service you use it with. 🤝

---


This README was **written using AI** 
