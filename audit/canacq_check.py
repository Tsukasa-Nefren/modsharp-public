"""Emulate FindFunctionFromReferences for CCSPlayer_ItemServices::CanAcquire with candidate refs.
usage: CS2_GAME=<dir containing bin/ and csgo/> python canacq_check.py <server.games.jsonc>
Prints, per platform and per candidate refs block, the refs status and whether it resolves to the signature's function.
"""
import sys, audit, resolver, cvars, jsonc
resolver.CVAR_HOOK = cvars.hook
j = jsonc.loads(open(sys.argv[1], encoding="utf-8").read())
E = j["Addresses"]["CCSPlayer_ItemServices::CanAcquire"]
CVARS = ["ammo_grenade_limit_total", "mp_buy_allow_grenades", "mp_buy_allow_guns", "mp_max_armor",
         "mp_warmup_items_nocount_policy", "mp_weapons_allow_typecount", "mp_weapons_allow_zeus",
         "mp_weapons_max_gun_purchases_per_weapon_per_match"]
CANDS = [("current", E.get("refs"))] + [(c, {"cvars": [c]}) for c in CVARS]
for plat in ("windows", "linux"):
    m = audit.module("server", plat, "new")
    sig = m.find_pattern_multi(E[plat])
    print(plat, "signature hits", [hex(x) for x in sig])
    for name, refs in CANDS:
        e = dict(E); e["refs"] = refs; log = []
        st, addr, cand = resolver.find_refs(m, e, log)
        if st == "Success":
            res = "OK" if addr in sig else "WRONG FUNCTION %#x" % addr
        elif st == "Ambiguous":
            res = "ambiguous(%d), signature %s" % (len(cand), "picks it" if any(x in sig for x in cand) else "matches none")
        else:
            res = "%s -> signature fallback" % st
        print("  %-52s %s" % (name, res))
