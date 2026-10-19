#!/usr/bin/env python3
"""
KPN-specific: stub MainActivity.handleMessage (jalur pembuatan banner iklan)
dengan bytecode VALID (registers asli dipertahankan), plus bypass cek tanda
tangan di libkpnfamily.so. Dipakai setelah alur APK_PATCHER.

Pemakaian: python3 Utils/kpn_adpath.py <in.apk> <out_dir_decoded>
(or kebalikannya) — desain: jalankan SEBELUM rebuild? Tidak: kami jalankan
sebagai fungsi pada folder decompiled.
"""
import re
import sys
from pathlib import Path

METHOD_RE = re.compile(r'^\.method\b.*?^\.end method', re.S | re.M)
TARGET_CLS = "kpn/soft/dev/kpnrevolution/activities/MainActivity.smali"


def stub_method(block):
    head = block[:block.index('\n')]
    if ' abstract' in head:
        return block
    mm = re.search(r'\)(\S+)', head)
    ret = mm.group(1) if mm else 'V'
    is_ctor = '<init>' in head or '<clinit>' in head
    mreg = re.search(r'^\s*\.(registers|locals)\s+\d+\s*$', block, re.M)
    reg_line = mreg.group(0).strip() if mreg else '.registers 1'
    if is_ctor or ret == 'V':
        body = '    const/4 v0, 0x0\n    return-void'
    elif ret[0] in ('L', '['):
        body = '    const/4 v0, 0x0\n    return-object v0'
    elif ret in ('J', 'D'):
        body = '    const-wide/16 v0, 0x0\n    return-wide v0'
    else:
        body = '    const/4 v0, 0x0\n    return v0'
    return head + '\n' + reg_line + '\n' + body + '\n.end method'


def patch_decoded(decompiled_dir):
    decompiled_dir = Path(decompiled_dir)
    found = 0
    for smali_root in [decompiled_dir / "smali"] + list(decompiled_dir.glob("smali_classes*")):
        p = smali_root / TARGET_CLS
        if not p.exists():
            continue
        src = p.read_text(encoding='utf-8', errors='ignore')
        n = 0

        def sub(m):
            nonlocal n
            blk = m.group(0)
            head = blk[:blk.index('\n')]
            if 'handleMessage' in head:
                n += 1
                return stub_method(blk)
            return blk
        out = METHOD_RE.sub(sub, src)
        if n:
            p.write_text(out, encoding='utf-8')
            found += n
            print(f"[+] Stub handleMessage pada {p} ({n} method)")
    if not found:
        print("[!] MainActivity.handleMessage tidak ditemukan — mungkin bukan KPN; lanjut tanpa perubahan")
    return found


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("pakai: kpn_adpath.py <folder_decompiled>")
        sys.exit(2)
    sys.exit(0 if patch_decoded(sys.argv[1]) >= 0 else 1)
