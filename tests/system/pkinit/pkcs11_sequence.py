#!/usr/bin/env python3
"""Summarize an OpenSC pkcs11-spy log as the PKCS#11 API call sequence.

Usage:
    pkcs11_sequence.py SPY_LOG
    pkcs11_sequence.py --selftest   # parser self-check (run by tofu.sh)

Turns the spy's per-call transcript (every Cryptoki call, its arguments,
its return value -- tens of KB per kinit) into the sequence a reader
actually wants for an audit: the calls in order, consecutive repeats
folded to ``xN``, each call annotated with the arguments that identify
what it did (token and object labels, the signature mechanism, the key
type). Input is the file the ``--pkcs11-spy`` option of setup.py writes;
see docs/local-ci.md.

Output shape:

    C_Initialize
    C_GetSlotList x2
    C_GetTokenInfo
    C_Login
    C_FindObjectsInit [object=mldsakey]
    C_FindObjects x2
    C_SignInit [CKM_ML_DSA]
    ...

Unparseable lines are ignored: this only ever reports what the log holds.
"""

import os
import re
import sys

# One logged call: "42: C_SignInit" (the spy's own per-call header).
CALL_RE = re.compile(r"^\s*\d+: (C_\w+)\s*$")
# Argument lines worth keeping: the ones that say what was acted on.
MECHANISM_RE = re.compile(r"pMechanism->type = (\S+)")
# An attribute template row: the CKA_LABEL row is followed by the spy's
# hex dump of the label bytes on the next line.
CLASS_RE = re.compile(r"CKA_CLASS\s+(CKO_\w+)")
LABEL_RE = re.compile(r"CKA_LABEL\s+0x?[0-9a-fA-F]+\s*/\s*(\d+)")
HEX_RE = re.compile(r"^\s+((?:[0-9a-fA-F]{2,8})+(?:\s+[0-9a-fA-F]{2,8})*)\s*$")

# Annotations are collected per call and only the interesting ones are
# emitted; a FindObjects template with no CKA_LABEL gets no annotation.
MAX_LABEL_CHARS = 60


def label_annotation(hexdump):
    """Decode the spy's hex byte dump of a CKA_LABEL back to the label."""
    digits = re.sub(r"\s+", "", hexdump)
    if len(digits) % 2:
        digits = digits[:-1]  # a truncated final byte, if the log cut it
    try:
        raw = bytes.fromhex(digits)
    except ValueError:
        return ""
    text = raw.decode("utf-8", errors="replace")
    text = "".join(ch if ch.isprintable() else "" for ch in text).strip()
    return text[:MAX_LABEL_CHARS]


def summarize(path):
    # Each emitted entry is [name, annotation, count]; consecutive
    # same-name calls without annotations fold into one entry with a
    # count.
    entries = []
    call = None
    notes = []

    def emit():
        if call is None:
            return
        note = next(iter(notes), "")
        if entries and entries[-1][0] == call and not note and not entries[-1][1]:
            entries[-1][2] += 1
        else:
            entries.append([call, note, 1])

    want_label_len = None  # set after a CKA_LABEL row; next hex line is it
    obj_class = ""

    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = CALL_RE.match(line)
            if m:
                emit()
                call = m.group(1)
                notes = []
                want_label_len = None
                obj_class = ""
                continue
            if call is None:
                continue
            if call.startswith("C_FindObjectsInit"):
                m = CLASS_RE.search(line)
                if m:
                    obj_class = m.group(1)[len("CKO_"):].lower()
                    continue
                m = LABEL_RE.search(line)
                if m:
                    want_label_len = int(m.group(1))
                    continue
                if want_label_len is not None:
                    m = HEX_RE.match(line)
                    if m:
                        text = label_annotation(m.group(1))
                        if text:
                            notes.append(
                                f"{obj_class} {text}".strip()
                                if obj_class else f"label={text}"
                            )
                    want_label_len = None
                continue
            m = MECHANISM_RE.search(line)
            if m and call in ("C_SignInit", "C_VerifyInit", "C_EncryptInit",
                              "C_DecryptInit", "C_DeriveKey"):
                notes.append(m.group(1))

    emit()
    return [
        f"{name} [{note}]" if note
        else f"{name} x{count}" if count > 1
        else name
        for name, note, count in entries
    ]


SELFTEST_LOG = """
*************** OpenSC PKCS#11 spy *****************
0: C_Initialize
[in] pInitArgs = (nil)
Returned:  0 CKR_OK
1: C_GetSlotList
[in] tokenPresent = 0x0
Returned:  0 CKR_OK
2: C_GetSlotList
[in] tokenPresent = 0x1
Returned:  0 CKR_OK
3: C_FindObjectsInit
[in] hSession = 0x3
[in] pTemplate[2]:
    CKA_CLASS             CKO_PRIVATE_KEY
    CKA_LABEL             000055564afce460 / 5
    61 61 61 61 61
     a a a  a a
Returned:  0 CKR_OK
4: C_FindObjects
Returned:  0 CKR_OK
5: C_SignInit
[in] pMechanism->type = CKM_ECDSA
Returned:  0 CKR_OK
6: C_Sign
Returned:  0 CKR_OK
"""

SELFTEST_EXPECT = [
    "C_Initialize",
    "C_GetSlotList x2",
    "C_FindObjectsInit [private_key aaaaa]",
    "C_FindObjects",
    "C_SignInit [CKM_ECDSA]",
    "C_Sign",
]


def selftest():
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
        f.write(SELFTEST_LOG)
        path = f.name
    try:
        got = summarize(path)
    finally:
        os.unlink(path)
    if got != SELFTEST_EXPECT:
        print("selftest FAILED:\n" + "\n".join(got), file=sys.stderr)
        return 1
    return 0


def main(argv):
    if len(argv) == 2 and argv[1] == "--selftest":
        return selftest()
    if len(argv) != 2:
        print(f"usage: {argv[0]} SPY_LOG | --selftest", file=sys.stderr)
        return 2
    try:
        seq = summarize(argv[1])
    except FileNotFoundError:
        print(f"(no PKCS#11 audit log: {argv[1]})", file=sys.stderr)
        return 0
    if not seq:
        print("(PKCS#11 audit log holds no calls)", file=sys.stderr)
        return 0
    print("\n".join(seq))
    print(f"\n{len(seq)} entries")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
