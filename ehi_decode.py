#!/usr/bin/env python3
import argparse
import base64
import binascii
import hashlib
import hmac
import io
import json
import os
import re
import struct
import sys
import zipfile

__version__ = "1.0.0"
PROG = "ehi_decode"
EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_DEPS = 3
EXIT_INTERRUPT = 130

_MISSING = []
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError:
    _MISSING.append("cryptography>=44")
try:
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt as xchacha_open
except ImportError:
    _MISSING.append("pynacl")

_LOG = sys.stdout


def log(msg=""):
    _LOG.write(msg + "\n")
    _LOG.flush()


def require_deps():
    if _MISSING:
        sys.stderr.write("error: missing dependencies: %s\n" % ", ".join(_MISSING))
        sys.stderr.write("install with: pip install %s\n" % " ".join(_MISSING))
        raise SystemExit(EXIT_DEPS)

CERT_ENTRIES = ("META-INF/CERT.RSA", "META-INF/EVOZI.RSA", "META-INF/BNDLTOOL.RSA")

DEFAULT_FINGERPRINT = "HQtE++2zpVC/+pTUo0REitSmsGM="
PACKAGE_NAME = "com.evozi.injector"
APP_NAME = "HTTP Injector"
SALT_SEP = "寫程戲師外"
PBKDF2_ITERATIONS = 5000

_sb = lambda t: bytes(x & 0xff for x in t)
IV_PREFIX = {
    "a0":    _sb((0x52, 0x2b, 0x01, 0x43, 0x3a, 0x5e)),
    "a00":   _sb((0x33, 0x7a, 0x10, 0x35, 0xaa, 0xed)),
    "a000":  _sb((0x2c, 0x5d, 0x11, 0x47, 0xbb, 0xad)),
    "a0000": _sb((0x4a, 0x2a, 0x24, 0x26, 0x4a, 0x44)),
}
IV_SUFFIX = {
    "a0":    _sb((-117, 47, -57, 84, -98, 26, -45, 104, -27, 65)),
    "a00":   _sb((-13, 69, -116, -95, 103, -23, 45, 116, -72, 57)),
    "a000":  _sb((66, 43, 59, 51, 77, 77, 35, 95, 26, 83)),
    "a0000": _sb((50, 26, 43, 93, 51, 77, 68, 31, 58, 46)),
}
XXTEA_KEY = b"null=V5kU5+FFrY"
IL0_ALPHABET = "RkLC2QaVMPYgGJW/A4f7qzDb9e+t6Hr0Zp8OlNyjuxKcTw1o5EIimhBn3UvdSFXs"
IL0_DEFAULT_SALT = b"EVZJNI"
_STD_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_IL0_TR = str.maketrans(IL0_ALPHABET + "?", _STD_B64 + "=")
TUNNEL_HEADER = bytes((0x01, 0x05, 0, 0, 0, 0, 0x00, 0x01, 0x00, 0x04))

PROFILE_FIELDS = frozenset((
    'configExpiryTimestamp', 'configHwid', 'configIdentifier',
    'configLockMobileOperatorId', 'configMessage', 'configSalt',
    'configTimestamp', 'configVersionCode', 'customDns1', 'customDns2',
    'customRoutes', 'dnsType', 'dnsttDnsResolverAddr', 'dnsttNameserver',
    'dnsttPublicKey', 'dnsttResolverMode', 'dnsttResolverProfile',
    'excludedRoutes', 'host', 'htrAlpn', 'htrAuthPassword', 'htrCustomCA',
    'htrDisableMtuDiscovery', 'htrMaxDownloadSpeed', 'htrMaxUploadSpeed',
    'htrObfsPassword', 'htrPortHoppingInterval', 'htrProtocol',
    'htrQuicRecvWindowSize', 'htrServerHost', 'htrServerPort', 'htrSni',
    'htrTc', 'htrTlsAllowInsecure', 'htrVersion', 'httpObfsSettings',
    'isConfigLock', 'isDefaultRoute', 'isPublicKey', 'isSshPrivateKey',
    'localPort', 'lockModes', 'lockModesHash', 'overwriteServerData',
    'overwriteServerProxyPort', 'overwriteServerType', 'password',
    'payload', 'port', 'publicKey', 'remoteProxy', 'remoteProxyAuth',
    'remoteProxyPassword', 'remoteProxyUsername',
    'shadowsocksEncryptionMethod', 'shadowsocksHost',
    'shadowsocksPassword', 'shadowsocksPort', 'sniHostname',
    'sshPrivateKey', 'tlsVersion', 'tunnelType', 'user', 'v2rAlterId',
    'v2rCoreType', 'v2rFlowType', 'v2rFragmentEnabled',
    'v2rFragmentInterval', 'v2rFragmentLength', 'v2rFragmentPackets',
    'v2rGrpcServiceName', 'v2rH2Host', 'v2rH2Path', 'v2rHost',
    'v2rHttpHost', 'v2rHttpPath', 'v2rIsGuiMode', 'v2rKcpHeaderType',
    'v2rKcpMtu', 'v2rKcpTti', 'v2rLocalAddrIp', 'v2rMtu',
    'v2rMuxConcurrency', 'v2rMuxEnabled', 'v2rNetwork', 'v2rPassword',
    'v2rPort', 'v2rPrivateKey', 'v2rProtocol', 'v2rPublicKey',
    'v2rQuicHeaderType', 'v2rQuicKey', 'v2rQuicSecurity', 'v2rRawJson',
    'v2rRoutingRules', 'v2rRoutingStrategy', 'v2rSsSecurity',
    'v2rTcpHeaderType', 'v2rTleAlpn', 'v2rTleFingerprintType',
    'v2rTleRealityMldsa65Verify', 'v2rTleRealityPublicKey',
    'v2rTleRealityShortID', 'v2rTleRealitySpiderX', 'v2rTleSecurityType',
    'v2rTlsAllowInsecure', 'v2rTlsAlpn', 'v2rTlsSni', 'v2rUserId',
    'v2rVlessSecurity', 'v2rVmessSecurity', 'v2rWgPreSharedKey',
    'v2rWgReserved', 'v2rWsHeader', 'v2rWsPath',
))

CONFIG_MESSAGE_KEY = b"EHIMSG"

SHELL_FIELDS = frozenset((
    'configAesKey', 'configData', 'configExpiryTimestamp', 'configHwid',
    'configIdentifier', 'configLockMobileOperatorId', 'configSalt',
    'configTimestamp', 'configVersionCode', 'lockModes', 'lockModesHash',
))
ARGON2 = dict(iterations=5, memory_cost=65536, lanes=4, length=32)
AAD_LEN = 0x1a


def stage_error(stage, msg):
    err = RuntimeError("stage %s: %s" % (stage, msg))
    err.stage, err.msg = stage, msg
    return err


def parse_header(d):
    if len(d) < 40:
        raise stage_error("0-header", "file is only %d bytes" % len(d))
    p = 0
    n = struct.unpack_from(">H", d, p)[0]; p += 2
    magic = d[p:p+n].decode("utf-8", "replace"); p += n
    if magic != "ehi":
        raise stage_error("0-header", "bad magic %r" % magic)
    fmt, vcode = struct.unpack_from(">ii", d, p); p += 8
    m = struct.unpack_from(">H", d, p)[0]; p += 2
    vname = d[p:p+m].decode("utf-8", "replace"); p += m
    ts, plen, flag, tag = struct.unpack_from(">qiiI", d, p); p += 20
    body = d[p:]
    if len(body) != plen:
        raise stage_error("0-header", "declared %d != actual %d" % (plen, len(body)))
    if plen % 16:
        raise stage_error("0-header", "payload %d not a block multiple" % plen)
    return {"magic": magic, "formatVersion": fmt, "appVersionCode": vcode,
            "appVersionName": vname, "exportedAtMillis": ts,
            "payloadLength": plen, "headerFlag": flag,
            "headerTag": "0x%08x" % tag}, body


def open_apk(path):
    z = zipfile.ZipFile(path)
    names = z.namelist()
    if "base.apk" in names:
        return zipfile.ZipFile(io.BytesIO(z.read("base.apk")))
    if "AndroidManifest.xml" in names:
        return z
    raise stage_error("1-key", "%s is not an APK or .apks bundle" % path)


def cert_fingerprint(apk):
    for entry in CERT_ENTRIES:
        try:
            blob = apk.read(entry)
        except KeyError:
            continue
        certs = pkcs7.load_der_pkcs7_certificates(blob)
        if certs:
            der = certs[0].public_bytes(Encoding.DER)
            return base64.b64encode(hashlib.sha1(der).digest()).decode(), entry
    raise stage_error("1-key", "no signing cert (looked for %s)" % ", ".join(CERT_ENTRIES))


def inner_keys(fp):
    sb = APP_NAME + SALT_SEP + fp + APP_NAME[3:9]
    salt = re.sub(r"[-=+/]", "", re.sub(r"\s+", "", sb)).encode("utf-8")
    kb = hashlib.pbkdf2_hmac("sha1", PACKAGE_NAME.encode(), salt, PBKDF2_ITERATIONS, 48)
    return kb[:16], kb[16:48], salt


def aes_cbc(key, iv, ct, stage):
    if len(ct) % 16:
        raise stage_error(stage, "ciphertext %d not a block multiple" % len(ct))
    pt = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor().update(ct)
    pad = pt[-1]
    if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
        raise stage_error(stage, "PKCS7 padding invalid (0x%02x)" % pad)
    return pt[:-pad]


M32, DELTA = 0xffffffff, 0x9e3779b9


def _mx(y, z, s, k, e, p):
    return ((((z >> 5) ^ ((y << 2) & M32)) + ((y >> 3) ^ ((z << 4) & M32))) ^
            (((s ^ y) + (k[(p & 3) ^ e] ^ z)) & M32)) & M32


def xxtea_unframe(blob, stage):
    if len(blob) % 4 or len(blob) < 8:
        raise stage_error(stage, "XXTEA input %d not a word multiple >= 8" % len(blob))
    v = list(struct.unpack("<%dI" % (len(blob) // 4), blob))
    k = list(struct.unpack("<4I", XXTEA_KEY.ljust(16, b"\0")))
    n = len(v)
    rounds = 52 // n + 6
    s = (rounds * DELTA) & M32
    y = v[0]
    while rounds > 0:
        e = (s >> 2) & 3
        for p in range(n - 1, 0, -1):
            v[p] = y = (v[p] - _mx(y, v[p-1], s, k, e, p)) & M32
        v[0] = y = (v[0] - _mx(y, v[n-1], s, k, e, 0)) & M32
        s = (s - DELTA) & M32
        rounds -= 1
    declared = v[-1]
    lo, hi = (n - 2) * 4, (n - 1) * 4
    if not (lo < declared <= hi):
        raise stage_error(stage, "declared length %d outside (%d, %d]" % (declared, lo, hi))
    return struct.pack("<%dI" % (n - 1), *v[:-1])[:declared]


def il0(salt, data):
    if not isinstance(data, str) or not data:
        return None
    try:
        dec = base64.b64decode(data[::-1].translate(_IL0_TR))
        hx = dec.decode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not hx or len(hx) % 2 or any(c not in "0123456789ABCDEF" for c in hx):
        return None
    raw = bytes.fromhex(hx)
    key = salt.encode("utf-8") if salt else IL0_DEFAULT_SALT
    return bytes(raw[i] ^ key[i % len(key)] for i in range(len(raw)))


def xor_b64(s, key):
    pad = "=" * (-len(s) % 4)
    raw = base64.b64decode(s + pad)
    return bytes(raw[i] ^ key[i % len(key)] for i in range(len(raw))).decode("utf-8", "replace")


def tunnel_key(cfg):
    exp = cfg.get("configExpiryTimestamp")
    parts = [cfg.get("configAesKey"), cfg.get("configIdentifier"),
             cfg.get("configSalt"), str(cfg.get("configTimestamp")),
             str(exp) if exp is not None else "0",
             cfg.get("lockModes"), cfg.get("lockModesHash"),
             cfg.get("configHwid"), cfg.get("configLockMobileOperatorId")]
    joined = "".join(p for p in parts if p)
    return hashlib.sha256(joined.encode("utf-8")).digest(), joined


def decode(path, apk_path, verbose=False, fingerprint=None, show=True):
    rep = {"file": path, "stages": []}

    def ok(stage, note):
        rep["stages"].append({"stage": stage, "note": note})
        if verbose:
            log("    [ok] %-14s %s" % (stage, note))

    with open(path, "rb") as fh:
        raw = fh.read()

    hdr, body = parse_header(raw)
    rep["header"] = hdr
    ok("0-header", "ehi v%d  app %s (%d)  payload %d B"
       % (hdr["formatVersion"], hdr["appVersionName"],
          hdr["appVersionCode"], hdr["payloadLength"]))

    if fingerprint:
        fp, entry = fingerprint, "supplied"
    elif apk_path:
        fp, entry = cert_fingerprint(open_apk(apk_path))
    else:
        fp, entry = DEFAULT_FINGERPRINT, "built-in default"
    okey = hashlib.sha256(fp.encode("utf-8")).digest()
    rep["signingCertEntry"], rep["certFingerprintB64"] = entry, fp
    ok("1-key", "%s  fp %s" % (entry, fp))

    civ = None
    last = None
    for variant in ("a0", "a00", "a000", "a0000"):
        iv = IV_PREFIX[variant] + IV_SUFFIX[variant]
        try:
            pt = aes_cbc(okey, iv, body, "2-aes-outer")
        except RuntimeError as e:
            last = e
            continue
        if all(32 <= c < 127 for c in pt[:16]):
            civ, rep["ivVariant"] = pt, variant
            break
        last = stage_error("2-aes-outer", "variant %s: block 0 not printable" % variant)
    if civ is None:
        raise last or stage_error("2-aes-outer", "no IV variant worked")
    ok("2-aes-outer", "AES-256/CBC/PKCS7 iv=%s -> %d B" % (rep["ivVariant"], len(civ)))

    parts = civ.split(b":")
    if len(parts) != 3:
        raise stage_error("3-civ", "expected 3 fields, got %d" % len(parts))
    try:
        iv2, mac, ct2 = (base64.b64decode(p, validate=True) for p in parts)
    except (binascii.Error, ValueError) as e:
        raise stage_error("3-civ", "base64 decode failed: %s" % e)
    if len(iv2) != 16 or len(mac) != 32:
        raise stage_error("3-civ", "iv %d mac %d" % (len(iv2), len(mac)))
    ok("3-civ", "iv 16 mac 32 ct %d" % len(ct2))

    ckey, ikey, _ = inner_keys(fp)
    ok("4-pbkdf2", "PBKDF2WithHmacSHA1 x%d -> 384 bit" % PBKDF2_ITERATIONS)

    if not hmac.compare_digest(hmac.new(ikey, iv2 + ct2, hashlib.sha256).digest(), mac):
        raise stage_error("5-hmac", "HMAC-SHA256 mismatch")
    ok("5-hmac", "HMAC-SHA256 verified")

    inner = aes_cbc(ckey, iv2, ct2, "6-aes-inner")
    ok("6-aes-inner", "AES-128/CBC/PKCS7 -> %d B" % len(inner))

    blob = xxtea_unframe(inner, "7-xxtea")
    ok("7-xxtea", "XXTEA -> %d B" % len(blob))

    try:
        shell = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise stage_error("8-json", "%s" % e)
    ok("8-json", "ConfigShell, %d keys" % len(shell))

    shell_real = {k: v for k, v in shell.items() if k in SHELL_FIELDS}
    shell_decoys = {k: v for k, v in shell.items() if k not in SHELL_FIELDS}
    result = {"envelope": hdr, "shell": shell_real, "shellDecoys": shell_decoys}
    ok("8-shell", "%d envelope fields, %d decoys"
       % (len(shell_real), len(shell_decoys)))
    if not shell.get("configData"):
        rep["ok"] = True
        return rep, result

    salt_str = shell.get("configSalt")
    b64 = il0(salt_str, shell["configData"])
    if b64 is None:
        raise stage_error("9-il0", "configData is not a well-formed Il0 string")
    container = base64.b64decode(b64, validate=True)
    if len(container) < 66 or container[:10] != TUNNEL_HEADER:
        raise stage_error("10-container", "bad header %s" % container[:10].hex())
    chdr, csalt, cnonce, cct = (container[:10], container[10:26],
                                container[26:50], container[50:])
    ok("9-il0", "%d B" % len(b64))
    ok("10-container", "hdr=%s salt=16 nonce=24 ct=%d" % (chdr.hex(), len(cct)))

    tk, joined = tunnel_key(shell)
    key = Argon2id(salt=csalt, **ARGON2).derive(tk)
    ok("11-kdf", "Argon2id(t=5,m=65536,p=4,32) over SHA-256 of %d chars" % len(joined))

    try:
        pt = xchacha_open(cct, container[:AAD_LEN], cnonce, key)
    except Exception:
        raise stage_error("11-aead", "Poly1305 tag did not verify")
    ok("11-aead", "XChaCha20-Poly1305 AUTHENTICATED -> %d B" % len(pt))

    try:
        profile = json.loads(pt.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise stage_error("12-json", "%s" % e)
    ok("12-json", "Profile, %d raw keys" % len(profile))

    genuine, decoys, encodings = {}, {}, {}
    for k, v in profile.items():
        if k not in PROFILE_FIELDS:
            decoys[k] = v
            continue
        if not isinstance(v, str) or v == "":
            genuine[k] = v
            encodings[k] = "raw"
            continue
        if k == "configMessage":
            genuine[k] = xor_b64(v, CONFIG_MESSAGE_KEY)
            encodings[k] = "base64+xor(EHIMSG)"
            continue
        dec = il0(salt_str, v)
        if dec is None:
            genuine[k] = v
            encodings[k] = "plain"
        else:
            try:
                genuine[k] = dec.decode("utf-8")
                encodings[k] = "Il0"
            except UnicodeDecodeError:
                genuine[k] = v
                encodings[k] = "plain"
    ok("13-fields", "%d genuine (%d Il0, %d plain), %d decoys"
       % (len(genuine), sum(1 for e in encodings.values() if e == "Il0"),
          sum(1 for e in encodings.values() if e == "plain"), len(decoys)))

    if show:
        dump(hdr, shell_real, genuine, encodings, envelope=verbose)

    result["profile"] = genuine
    result["profileDecoys"] = decoys
    result["profileFieldEncoding"] = encodings
    rep.update({"ok": True, "container": {
        "bytes": len(container), "header": chdr.hex(),
        "argon2Salt": csalt.hex(), "nonce": cnonce.hex(),
        "ciphertextBytes": len(cct), "aadBytes": AAD_LEN},
        "tunnelKeySha256": tk.hex(), "plaintextBytes": len(pt)})
    return rep, result


def dump(hdr, shell, profile, encodings, envelope=False):
    def section(title):
        log("\n  %s\n  %s" % (title, "-" * len(title)))

    if envelope:
        section("ENVELOPE (plaintext container header)")
        for k in ("magic", "formatVersion", "appVersionCode", "appVersionName",
                  "exportedAtMillis", "payloadLength", "headerFlag", "headerTag"):
            log("    %-22s %s" % (k, hdr[k]))

    section("SHELL (ConfigShell - envelope metadata)")
    for k in sorted(shell):
        v = shell[k]
        if k == "configData":
            v = "<%d chars, decrypted below>" % len(v)
        log("    %-22s %s" % (k, v))

    section("PROFILE (app configuration)")
    msg = None
    for k in sorted(profile):
        v = profile[k]
        if k == "configMessage" and isinstance(v, str) and v.strip():
            msg = v
            log("    %-22s <%d chars, shown below>" % (k, len(v)))
            continue
        enc = encodings.get(k, "raw")
        tag = "" if enc in ("raw", "plain") else "  [%s]" % enc
        if isinstance(v, str) and len(v) > 60:
            v = v[:57] + "..."
        log("    %-22s %r%s" % (k, v, tag))

    if msg:
        section("configMessage (decoded)")
        for line in msg.splitlines():
            log("    | %s" % line)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog=PROG,
        description="Decode HTTP Injector 6.5.0 .ehi configuration files.",
        epilog="originals are opened read-only and never modified; "
               "the APK only supplies Base64(SHA-1(signing cert)), so --fp "
               "replaces it and a wrong value cannot yield bad data - it "
               "fails the outer AES or the stage-5 HMAC. "
               "exit status: 0 ok, 1 a file failed, 2 usage, "
               "3 missing dependency, 130 interrupted.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="input .ehi files")
    ap.add_argument("--apk", help="APK or .apks providing the signing certificate")
    ap.add_argument("--fp", help="Base64(SHA-1(cert)) directly, instead of an APK")
    ap.add_argument("--outdir", default="decoded_full",
                    help="directory for the decoded JSON (default: decoded_full)")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="also show the per-stage log and container header")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="no dump, just write the JSON")
    ap.add_argument("--json", action="store_true",
                    help="emit the result JSON on stdout (progress -> stderr)")
    ap.add_argument("--version", action="version",
                    version="%(prog)s " + __version__)
    args = ap.parse_args(argv)

    if not args.files:
        ap.print_help()
        return EXIT_USAGE

    require_deps()

    if args.json:
        global _LOG
        _LOG = sys.stderr

    apk = args.apk
    if apk is None:
        here = os.path.dirname(os.path.abspath(__file__))
        for d in (os.getcwd(), here):
            for c in ("HTTP Injector_6.5.0.apks", "base.apk"):
                cand = os.path.join(d, c)
                if os.path.exists(cand):
                    apk = cand
                    break
            if apk:
                break
    if args.fp:
        apk = None
    elif not apk or not os.path.exists(apk):
        apk = None

    try:
        os.makedirs(args.outdir, exist_ok=True)
    except OSError as e:
        sys.stderr.write("error: cannot create %s: %s\n" % (args.outdir, e))
        return EXIT_USAGE

    reports, rc, payloads = [], EXIT_OK, {}
    for path in args.files:
        log("\n%s" % path)
        if not os.path.exists(path):
            log("    [FAIL] not found")
            rc = EXIT_FAIL
            reports.append({"file": path, "ok": False, "error": "not found"})
            continue
        if not os.path.isfile(path):
            log("    [FAIL] not a regular file")
            rc = EXIT_FAIL
            reports.append({"file": path, "ok": False,
                            "error": "not a regular file"})
            continue
        try:
            rep, result = decode(path, apk, verbose=args.verbose,
                                 fingerprint=args.fp, show=not args.quiet)
        except RuntimeError as e:
            stage = getattr(e, "stage", None)
            log("    [FAIL] %s" % e)
            rc = EXIT_FAIL
            entry = {"file": path, "ok": False, "error": getattr(e, "msg", str(e))}
            if stage:
                entry["failedStage"] = stage
            reports.append(entry)
            continue
        except OSError as e:
            log("    [FAIL] %s" % e)
            rc = EXIT_FAIL
            reports.append({"file": path, "ok": False, "error": str(e)})
            continue
        except Exception as e:
            log("    [FAIL] %s: %s" % (type(e).__name__, e))
            rc = EXIT_FAIL
            reports.append({"file": path, "ok": False,
                            "error": "%s: %s" % (type(e).__name__, e)})
            continue
        out = os.path.join(args.outdir,
                           os.path.splitext(os.path.basename(path))[0] + ".json")
        try:
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(result, fh, indent=2, ensure_ascii=False, sort_keys=True)
        except OSError as e:
            log("    [FAIL] cannot write %s: %s" % (out, e))
            rc = EXIT_FAIL
            reports.append({"file": path, "ok": False, "error": str(e)})
            continue
        log("    -> %s" % out)
        payloads[path] = result
        reports.append(rep)

    try:
        with open(os.path.join(args.outdir, "report.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(reports, fh, indent=2, ensure_ascii=False)
    except OSError as e:
        sys.stderr.write("error: cannot write report.json: %s\n" % e)
        rc = EXIT_FAIL

    if args.json:
        out = payloads if len(payloads) != 1 else next(iter(payloads.values()))
        sys.stdout.write(json.dumps(out, indent=2, ensure_ascii=False,
                                    sort_keys=True) + "\n")
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        sys.exit(EXIT_INTERRUPT)
