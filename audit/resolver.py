"""Emulation of gamedata.cpp FindAddress / FindFunctionFromReferences / GetVScriptFunction."""
import capstone
from capstone import x86 as X
import msemu

MD = msemu.new_md()
REG, IMM, MEM = X.X86_OP_REG, X.X86_OP_IMM, X.X86_OP_MEM


def dec(m, ip):
    code = m.read(ip, 15)
    if not code:
        return None
    return next(MD.disasm(code, ip), None)


def trim(s):
    return s.strip()


def find_refs(m, e, log):
    """FindFunctionFromReferences. returns (status, addr, candidates). status in NoReferences/Failed/Ambiguous/Success/Unverifiable"""
    refs = e.get("refs") or {}
    def lst(k):
        v = refs.get(k)
        if isinstance(v, str):
            return [v] if v else []
        return [x for x in (v or []) if isinstance(x, str) and x]
    strings, cvars, vts = lst("strings"), lst("cvars"), lst("vtables")
    from_vt = refs.get("vtable") if isinstance(refs.get("vtable"), str) else ""
    ref_sets = []
    for s in strings:
        if "[ptr]" not in s:
            a = m.find_string(s)
            if not a:
                log.append("string not found: %r" % s)
                return "Failed", 0, []
            r = m.refs_to(a)
            if not r:
                log.append("string has no code refs: %r" % s)
                return "Failed", 0, []
            ref_sets.append(r)
            continue
        sv = trim(s)
        if not sv:
            continue
        ss = trim(sv[:sv.find("[ptr]")])
        a = m.find_string(ss)
        if not a:
            log.append("[ptr] string not found (skipped): %r" % ss)
            continue
        merged = []
        for p in m.find_ptrs(a):
            merged += m.refs_to(p)
        if not merged:
            log.append("[ptr] string ptr has no refs: %r" % ss)
            return "Failed", 0, []
        ref_sets.append(merged)
    for v in vts:
        v = trim(v)
        if not v:
            continue
        if not v.endswith("[typeinfo]"):
            a = m.find_vtable(v)
            if not a:
                log.append("FATAL vtable not found: %s" % v)
                return "Failed", 0, []
            kind = "VTable"
        else:
            nm = trim(v[:-len("[typeinfo]")])
            a = m.typeinfo_from_name(nm)
            kind = "TypeInfo"
            if not a:
                log.append("typeinfo not found: %s" % nm)
                return "Failed", 0, []
        r = m.refs_to(a)
        if not r:
            log.append("%s %s has no code refs" % (kind, v))
            return "Failed", 0, []
        ref_sets.append(r)
    if cvars:
        cs = cvar_refsets(m, cvars, log)
        if cs is None:
            return "Unverifiable", 0, []
        if cs == "FAILED":
            return "Failed", 0, []
        ref_sets += cs
    if not ref_sets:
        return "NoReferences", 0, []
    matches = m.intersect(ref_sets)
    if not matches:
        log.append("intersection empty")
        return "Failed", 0, []
    if not from_vt:
        if len(matches) > 1:
            return "Ambiguous", 0, matches
    else:
        vf = set(m.vfuncs(from_vt))
        if not vf:
            log.append("no vfuncs from %s" % from_vt)
            return "Failed", 0, []
        inter = sorted(set(matches) & vf)
        if not inter:
            log.append("candidates %s not in vtable %s" % ([hex(m.rva(x)) for x in matches[:8]], from_vt))
            return "Failed", 0, []
        if len(inter) > 1:
            return "Ambiguous", 0, inter
        matches = inter
    return "Success", matches[0], matches


# cvar emulation hook (set by audit driver); returns list of ref sets or None if not emulable
CVAR_HOOK = None


def cvar_refsets(m, cvars, log):
    if CVAR_HOOK is None:
        log.append("cvar refs need the runtime ConVar pointer")
        return None
    return CVAR_HOOK(m, cvars, log)


def find_address(m, e, platform, log, vscript=True):
    """Emulate FindAddress for one platform. Returns dict."""
    sig = e.get(platform)
    factory = None
    if isinstance(sig, dict):
        factory = sig.get("factory")
        sig = sig.get("signature")
    has_sig = bool(sig)
    res = dict(sig_count=None, sig_addr=0, vs=None, ref=None, addr=0, how=None, cands=[])
    address = 0
    if vscript and e.get("vscript") and e.get("library", "").lower() == "server":
        a, alts = vscript_function(m, e["vscript"], log)
        res["vs"] = a
        res["vs_alts"] = alts
        if a:
            address = a
            res["how"] = "vscript"
        else:
            log.append("vscript '%s' failed -> fallback" % e["vscript"])
    ref_status = "Failed"
    if address == 0:
        has_refs = bool(e.get("refs"))
        ref_status, ra, cands = find_refs(m, e, log) if has_refs else ("NoReferences", 0, [])
        res["ref"] = ref_status
        res["cands"] = cands
        if ref_status == "Success":
            address = ra
            res["how"] = "refs"
            res["ref_addr"] = ra
    sig_found = False
    if has_sig:
        if sig.startswith("@") and " " not in sig:
            a = m.exports.get(sig[1:], 0)
            res["sig_count"] = 1 if a else 0
            res["sig_addr"] = a
            sig_found = bool(a)
        else:
            hits = m.find_pattern_multi(sig)
            res["sig_count"] = len(hits)
            res["sig_hits"] = hits
            if len(hits) == 1:
                res["sig_addr"] = hits[0]
                sig_found = True
    if address == 0 and ref_status == "Ambiguous":
        if sig_found and res["sig_addr"] in res["cands"]:
            address = res["sig_addr"]
            res["how"] = "refs-ambiguous+sig"
        else:
            log.append("ambiguous refs (%d) and sig %s" % (len(res["cands"]), "absent" if not has_sig else ("matched none" if sig_found else "did not resolve")))
    if address == 0 and sig_found:
        address = res["sig_addr"]
        res["how"] = "sig"
    if address and factory:
        for op in factory.split(" "):
            if not op:
                continue
            if op[0] == "r":
                address = address + 4 + m.i32(address)
            elif op[0] == "d":
                address = m.u64(address)
            else:
                try:
                    v = int(op[1:]) if op[0] in "+-" else int(op)
                except ValueError:
                    continue
                address = address - v if op[0] == "-" else address + v
        res["factory_addr"] = address
    res["addr"] = address
    res["unverifiable"] = (ref_status == "Unverifiable")
    return res


# ------------------------------------------------------------------ vscript
def _abs_mem(ins, op):
    if op.mem.base == X.X86_REG_RIP:
        return ins.address + ins.size + op.mem.disp
    if op.mem.base == 0 and op.mem.index == 0:
        return op.mem.disp & 0xFFFFFFFFFFFFFFFF
    return None


def decode_control_flow(m, start, win):
    ip = start
    if win:
        ins = dec(m, ip)
        if ins is None or not ins.operands or ins.operands[0].type != REG:
            return 0
        str_reg = ins.operands[0].reg
        ip += ins.size
        valid = False
        for _ in range(16):
            ins = dec(m, ip)
            if ins is None:
                break
            ops = ins.operands
            if ins.id == X.X86_INS_MOV and len(ops) > 1 and ops[0].type == MEM and ops[1].type == REG and ops[1].reg == str_reg:
                if ops[0].mem.disp in (0, 8):
                    valid = True
                    ip += ins.size
                    break
            ip += ins.size
        if not valid:
            return 0
    else:
        def is_idx_lea(ins):
            ops = ins.operands
            return (ins.id == X.X86_INS_LEA and len(ops) > 1 and ops[0].type == REG and ops[1].type == MEM
                    and ops[1].mem.base != 0 and ops[1].mem.base == ops[1].mem.index and ops[1].mem.scale == 4)
        valid = False
        for _ in range(16):
            ins = dec(m, ip)
            if ins is None:
                break
            if is_idx_lea(ins):
                valid = True
                ip += ins.size
                break
            ip += ins.size
        if not valid:
            fr = m.func_range(start)
            if fr and fr[0] < start:
                sip = fr[0]
                while sip < start:
                    ins = dec(m, sip)
                    if ins is None:
                        break
                    if is_idx_lea(ins):
                        valid = True
                        ip = start
                    sip += ins.size
        if not valid:
            return 0
    known = []
    regv = {}
    wrapper = 0
    for _ in range(128):
        ins = dec(m, ip)
        if ins is None:
            break
        ops = ins.operands
        mn = ins.id
        if mn == X.X86_INS_LEA and len(ops) > 1 and ops[1].type == MEM:
            t = _abs_mem(ins, ops[1])
            lt = t if t is not None else 0
            if ops[0].type == REG:
                regv[ops[0].reg] = lt
            if m.is_known_function_entry(lt) and lt not in known:
                known.append(lt)
        if mn in (X.X86_INS_MOV, X.X86_INS_MOVQ) and len(ops) > 1 and ops[0].type == MEM and ops[0].mem.disp == 0x38 and ops[1].type == REG:
            wrapper = regv.get(ops[1].reg, 0)
        if mn in (X.X86_INS_MOV, X.X86_INS_MOVQ, X.X86_INS_MOVAPS, X.X86_INS_MOVUPS) and len(ops) > 0 and ops[0].type == MEM:
            d = ops[0].mem.disp
            if d == 0x40 or d < 0:
                if len(ops) > 1 and ops[1].type == REG:
                    direct = regv.get(ops[1].reg, 0)
                    if direct != 0 and direct != wrapper:
                        return direct
                for k in reversed(known):
                    if k != wrapper and k != 0:
                        return k
        ip += ins.size
    return 0


def vscript_function(m, name, log):
    """returns (address, list of distinct per-ref results) -- ModSharp takes the first ref in its order."""
    win = m.kind == "pe"
    sa = m.find_string(name)
    results = []
    def try_refs(target):
        out = []
        if not target:
            return out
        for src in m.refs_to(target):
            r = decode_control_flow(m, src, win)
            if r:
                out.append((src, r))
        return out
    results = try_refs(sa)
    if not results:
        for p in m.find_ptrs(sa):
            results = try_refs(p)
            if results:
                break
    if not results:
        return 0, []
    distinct = sorted(set(r for _, r in results))
    if len(distinct) > 1:
        log.append("vscript '%s': refs disagree %s" % (name, [hex(m.rva(x)) for x in distinct]))
    return results[0][1], distinct
