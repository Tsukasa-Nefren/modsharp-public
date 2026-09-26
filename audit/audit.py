"""Run the ModSharp gamedata emulation for every Addresses entry.
usage: python audit.py <gamedata_dir> <build: new|old> <out.json>
"""
import sys, os, json, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import jsonc, msemu, resolver

DD = os.environ.get("CS2_GAME", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "bin", "game"))
OLDW = os.environ.get("OLDW", "")
OLDL_SERVER = os.environ.get("OLDL_SERVER", "")
LIBFILE = {"engine": "engine2", "server": "server"}


def lib_path(lib, plat, build):
    name = LIBFILE.get(lib, lib)
    if build == "new":
        root = DD
    else:
        if plat == "linux":
            return OLDL_SERVER if lib in ("server", "matchmaking") else None
        root = OLDW
    if plat == "windows":
        sub = "csgo\\bin\\win64" if lib in ("server", "matchmaking") else "bin\\win64"
        return os.path.join(root, sub, name + ".dll")
    sub = "csgo\\bin\\linuxsteamrt64" if lib in ("server", "matchmaking") else "bin\\linuxsteamrt64"
    return os.path.join(root, sub, "lib" + name + ".so")


_mods = {}


def module(lib, plat, build):
    p = lib_path(lib, plat, build)
    if not p or not os.path.exists(p):
        return None
    if p not in _mods:
        m = msemu.load(p)
        m.build_index(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache"))
        _mods[p] = m
    return _mods[p]


def main():
    gd, build, out = sys.argv[1], sys.argv[2], sys.argv[3]
    only = sys.argv[4] if len(sys.argv) > 4 else None
    import cvars
    resolver.CVAR_HOOK = cvars.hook
    results = []
    for f in sorted(glob.glob(os.path.join(gd, "*.games.jsonc"))):
        j = jsonc.loads(open(f, encoding="utf-8").read())
        for key, e in (j.get("Addresses") or {}).items():
            if only and only not in key:
                continue
            for plat in ("windows", "linux"):
                lib = e.get("library")
                sig = e.get(plat)
                has_refs = bool(e.get("refs"))
                registered = bool(sig) or has_refs
                r = dict(file=os.path.basename(f), key=key, plat=plat, lib=lib, registered=registered,
                         on_demand=bool(e.get("on_demand")), has_sig=bool(sig), has_refs=has_refs,
                         vscript=e.get("vscript"))
                if not registered:
                    r["status"] = "not-registered"
                    results.append(r)
                    continue
                m = module(lib, plat, build)
                if m is None:
                    r["status"] = "no-binary"
                    results.append(r)
                    continue
                log = []
                try:
                    res = resolver.find_address(m, e, plat, log)
                except Exception as ex:
                    import traceback
                    traceback.print_exc()
                    res = {"error": repr(ex), "addr": 0}
                # also evaluate refs separately when vscript succeeded (info only)
                def rv(a):
                    return hex(m.rva(a)) if a else None
                r.update(sig_count=res.get("sig_count"), sig_rva=rv(res.get("sig_addr")),
                         sig_hits=[rv(x) for x in (res.get("sig_hits") or [])[:6]],
                         vs_rva=rv(res.get("vs")), vs_alts=[rv(x) for x in res.get("vs_alts") or []],
                         ref=res.get("ref"), ref_rva=rv(res.get("ref_addr")),
                         cands=[rv(x) for x in (res.get("cands") or [])[:12]], ncands=len(res.get("cands") or []),
                         how=res.get("how"), addr_rva=rv(res.get("addr")), unverifiable=res.get("unverifiable"),
                         factory_rva=rv(res.get("factory_addr")), log=log, error=res.get("error"))
                r["status"] = "resolved" if res.get("addr") else ("unverifiable" if res.get("unverifiable") else "FAILED")
                results.append(r)
                print("%-18s %-55s %-7s %-12s sig=%s vs=%s ref=%s(%s) how=%s addr=%s %s" % (
                    r["file"][:18], key[:55], plat, r["status"], r["sig_count"], r["vs_rva"], r["ref"], r["ncands"], r["how"], r["addr_rva"],
                    "; ".join(log)[:200]), flush=True)
    json.dump(results, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
