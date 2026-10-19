#!/usr/bin/env python3
import os
import re
from pathlib import Path

AD_PACKAGES = [
    'com/google/android/gms/ads',
    'com/google/ads',
    'com/facebook/ads',
    'com/unity3d/ads',
    'com/applovin',
    'com/vungle',
    'com/ironsource',
    'com/adcolony',
    'com/chartboost',
    'com/inmobi',
    'com/mopub',
    'com/startapp',
    'com/admob',
    'com/google/android/gms/internal/ads',
]

METHOD_RE = re.compile(r'^\.method\b.*?^\.end method', re.S | re.M)


class Patch:
    def __init__(self):
        self.name = "Ads Patch"
        self.description = "Neutralize ad SDKs by stubbing their method bodies (dexer-safe)"

    def _is_ad_file(self, rel):
        return any(rel.startswith(p) for p in AD_PACKAGES)

    def _stub_method(self, block):
        first = block.split('\n', 0)
        head = block[:block.index('\n')]
        is_ctor = '<init>' in head or '<clinit>' in head
        mm = re.search(r'\)(\S+)', head)
        ret = mm.group(1) if mm else 'V'
        if ' abstract' in head:
            return block
        head = re.sub(r'\s+native\b', '', head)
        mreg = re.search(r'^\s*\.(registers|locals)\s+(\d+)\s*$', block, re.M)
        reg_line = mreg.group(0).strip() if mreg else '.registers 1'
        if is_ctor or ret == 'V':
            body = ['    const/4 v0, 0x0', '    return-void']
        elif ret[0] in ('L', '['):
            body = ['    const/4 v0, 0x0', '    return-object v0']
        elif ret in ('J', 'D'):
            body = ['    const-wide/16 v0, 0x0', '    return-wide v0']
        else:  # Z B S I F
            body = ['    const/4 v0, 0x0', '    return v0']
        return head + "\n" + reg_line + "\n" + "\n".join(body) + "\n.end method"

    def apply(self, decompiled_dir, args):
        print(f"[+] Applying {self.name}")
        base = Path(decompiled_dir)
        smali_roots = [base / d for d in os.listdir(base)
                       if d == 'smali' or d.startswith('smali_classes')]
        if not smali_roots:
            print("[-] smali directory not found")
            return False

        total = 0
        for smali_dir in smali_roots:
            for smali_file in smali_dir.rglob("*.smali"):
                rel = str(smali_file.relative_to(smali_dir)).replace(os.sep, '/')
                if not self._is_ad_file(rel):
                    continue
                try:
                    content = smali_file.read_text(encoding='utf-8', errors='ignore')
                    stubbed = METHOD_RE.sub(lambda m: self._stub_method(m.group(0)), content)
                    if stubbed != content:
                        smali_file.write_text(stubbed, encoding='utf-8')
                        total += 1
                except Exception as e:
                    print(f"[-] Error patching {smali_file}: {e}")

        print(f"[+] Stubbed ad files: {total}")
        return total > 0
