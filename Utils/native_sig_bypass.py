#!/usr/bin/env python3
"""
Native signature-check bypass untuk APK.

NOP-out conditional branch "tanda tangan salah" di JNI_OnLoad library native,
berdasarkan pola: instruksi yang memuat konstanta magic (movw/movt/arm64 imm
atau cmp imm) diikuti branch condisional BACKWARD ke fail-stub.

Dipakai sebagai standalone step di workflow:
    python3 Utils/native_sig_bypass.py <in.apk> <out.apk> [--const LO HI] [--lib NAME]

Butuh: pyelftools, capstone (pip install pyelftools capstone).
Default target: libkpnfamily.so (KPN Tunnel Revolution, const 0xde3ee7c3/0xbe6a4da4).
Aman dipanggil pada APK tanpa target: tidak mengubah apa pun.
"""
import argparse
import shutil
import sys
import zipfile
from pathlib import Path

from elftools.elf.elffile import ELFFile
from capstone import (Cs, CS_ARCH_ARM64, CS_ARCH_ARM, CS_ARCH_X86,
                      CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_32, CS_MODE_64)

# konstanta pembanding hash sertifikat pada target
CONST_LO = 0xe7c3
CONST_HI = 0xde3e
ALT_LO = 0x4da4
ALT_HI = 0xbe6a


def jni_sym(elf):
    for s in elf.get_section_by_name('.dynsym').iter_symbols():
        if s.name == 'JNI_OnLoad' and s['st_value']:
            return s['st_value'], s['st_size']
    return None, None


def patch_one_lib(data):
    """Return (patched_bytes, info) atau (None, reason)."""
    import io
    elf = ELFFile(io.BytesIO(data))
    mach = elf.header.e_machine
    sym, size = jni_sym(elf)
    if sym is None:
        return None, "no JNI_OnLoad"
    text = elf.get_section_by_name('.text')
    if text is None:
        return None, "no .text"
    base, soff, td = text['sh_addr'], text['sh_offset'], text.data()

    if mach == 'EM_AARCH64':
        arch, mode, v = CS_ARCH_ARM64, CS_MODE_ARM, sym
        NOP = bytes.fromhex('1f2003d5')
    elif mach == 'EM_ARM':
        v = sym & ~1
        thumb = bool(sym & 1)
        arch, mode = CS_ARCH_ARM, (CS_MODE_THUMB if thumb else CS_MODE_ARM)
        NOP = b'\xbf\x00'
    elif mach == 'EM_386':
        arch, mode, v = CS_ARCH_X86, CS_MODE_32, sym
        NOP = b'\x90'
    elif mach == 'EM_X86_64':
        arch, mode, v = CS_ARCH_X86, CS_MODE_64, sym
        NOP = b'\x90'
    else:
        return None, f"mach {mach} tidak didukung"

    fsize = size or 1200
    body = td[v - base: v - base + fsize]
    raw = bytearray(data)
    md = Cs(arch, mode)
    try:
        insns = list(md.disasm(body, v))
    except Exception as e:
        return None, f"disasm error {e}"

    def has_const(ins):
        o = ins.op_str
        return any(t in o for t in (f'0x{CONST_LO:x}', f'0x{CONST_HI:x}',
                                    f'0x{ALT_LO:x}', f'0x{ALT_HI:x}',
                                    f'0x{CONST_HI << 16 | CONST_LO:x}',
                                    f'0x{ALT_HI << 16 | ALT_LO:x}'))

    patched = []
    for i, ins in enumerate(insns):
        if not has_const(ins):
            continue
        for j in range(i, min(i + 8, len(insns))):
            cand = insns[j]
            m = cand.mnemonic.split('.')[0]
            if m not in ('beq', 'bne', 'je', 'jne') and cand.mnemonic not in ('b.eq', 'b.ne'):
                continue
            toks = cand.op_str.replace(',', ' ').split()
            if not toks:
                continue
            try:
                target = int(toks[-1].lstrip('#'), 0)
            except ValueError:
                continue
            if target >= cand.address:      # hanya branch mundur = fail-stub
                continue
            a = soff + (cand.address - base)
            nopp = (NOP * ((cand.size + len(NOP) - 1) // len(NOP)))[:cand.size]
            raw[a:a + cand.size] = nopp
            patched.append((hex(cand.address), cand.mnemonic, cand.op_str))
            break
    if not patched:
        return None, "pola tidak ketemu"
    return bytes(raw), str(patched)


def patch_apk(in_apk, out_apk, lib_filter=None):
    lib_filter = lib_filter or 'libkpnfamily.so'
    results = []
    with zipfile.ZipFile(in_apk) as zin:
        names = zin.namelist()
        with zipfile.ZipFile(out_apk, 'w', zipfile.ZIP_DEFLATED) as zout:
            for it in zin.infolist():
                data = zin.read(it.filename)
                if it.filename.startswith('lib/') and it.filename.endswith(lib_filter):
                    patched, info = patch_one_lib(data)
                    if patched is not None:
                        data = patched
                        results.append(f"{it.filename} :: {info}")
                    else:
                        results.append(f"{it.filename} :: SKIP ({info})")
                zout.writestr(it, data)
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('in_apk')
    ap.add_argument('out_apk')
    ap.add_argument('--lib', default='libkpnfamily.so')
    a = ap.parse_args()
    if Path(a.out_apk).resolve() == Path(a.in_apk).resolve():
        print("[-] in/out harus beda file")
        return 2
    res = patch_apk(a.in_apk, a.out_apk, a.lib)
    if not res:
        print("[-] tidak ada lib target dalam APK")
        shutil.copy(a.in_apk, a.out_apk)
        return 0
    for r in res:
        print("[*]", r)
    if all('SKIP' in r or 'tidak' in r for r in res):
        shutil.copy(a.in_apk, a.out_apk)
        print("[!] tidak ada yang di-patch, salin apa adanya")
    else:
        print("[+] native sig-bypass OK")
    return 0


if __name__ == '__main__':
    sys.exit(main())
