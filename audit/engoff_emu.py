"""Static port of ModSharp's engine offset auto-resolvers.

Source ported (read-only):  msp_scratch/Engine/src/address_engine.cpp
    ResolveServerSideClientOffsets()   (15 CServerSideClient offsets)
    ResolveNetworkGameServerOffsets()  (3 CNetworkGameServer offsets)
Helpers ported:  address_scan.h (AnchorVFunctions, AnchorFunctions, ScanWithLeaves, FindUtlVectors,
    LeafFieldGetter, IsFieldMem, IsObjectBase, kThisReg), address_resolve.h (ResolveVote,
    VoteCandidates, try_overwrite_offset), memory/zydis_utility.h (ScanInstructions,
    GetBaseRegister, IsVolatileRegister, ResolveCallTarget, GetAbsoluteAddress).
Module primitives (FindString, GetReferenceRange, GetFunctionRange, FindFunctionFromStringRef,
    FindAllFunctionsFromStringRefs, GetVFunctionsFromVTable) come from msemu.py.

Zydis -> capstone mapping notes (APPROX where marked):
  * operand .size is in bits (capstone bytes * 8).
  * mem.disp.has_displacement is taken as disp != 0; every use in the resolvers also requires
    disp > 0, so the distinction never matters.
  * ZYDIS_ATTRIB_IS_RELATIVE = relative branch (imm operand of call/jmp/jcc/loop) or any
    RIP-relative memory operand.
  * operands[i].actions & WRITE = capstone op.access & CS_AC_WRITE.
  * Zydis exposes hidden operands after the visible ones; the resolvers only read operands[0] of
    arbitrary instructions in two places (pending-register write check, FindUtlVectors clobber
    check). For the sign-extension family (cdqe/cwde/cbw/cdq/cqo/cwd) whose only operands are
    hidden, operands[0] is synthesised as the implicitly written register (APPROX).
  * ResolveCallTarget: `call [mem]` dereferences the static (relocated) image; PLT stubs are
    followed through their GOT slot exactly as the C++ does; unresolved imports become a sentinel
    outside every function range (APPROX: at runtime they point into another module, same effect).

usage: python engoff_emu.py [linux|windows|both] [--json out.json]
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, r"C:\tmp\modsharp_update")
import capstone
from capstone import x86 as X
import audit, jsonc

MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
MD.detail = True

# ------------------------------------------------------------------ Zydis-like decode
_GPR = {
    "rax": "al ah ax eax", "rbx": "bl bh bx ebx", "rcx": "cl ch cx ecx", "rdx": "dl dh dx edx",
    "rsi": "sil si esi", "rdi": "dil di edi", "rbp": "bpl bp ebp", "rsp": "spl sp esp", "rip": "ip eip",
}
for _i in range(8, 16):
    _GPR["r%d" % _i] = "r%db r%dw r%dd" % (_i, _i, _i)
BASE = {}
for _full, _subs in _GPR.items():
    BASE[_full] = _full
    for _s in _subs.split():
        BASE[_s] = _full


def base_reg(name):
    """ZydisUtility::GetBaseRegister (largest enclosing GPR); non-GPRs map to themselves."""
    if name is None:
        return None
    return BASE.get(name, name)


VOLATILE_COMMON = {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}

MNEM_ALIAS = {X.X86_INS_MOVABS: X.X86_INS_MOV}
SIGNEXT_HIDDEN = {X.X86_INS_CDQE: "rax", X.X86_INS_CWDE: "rax", X.X86_INS_CBW: "rax",
                  X.X86_INS_CDQ: "rdx", X.X86_INS_CQO: "rdx", X.X86_INS_CWD: "rdx"}
REL_BRANCH_GROUPS = (capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL)


class Op:
    __slots__ = ("type", "size", "reg", "base", "index", "disp", "scale", "write", "imm")

    def __init__(self):
        self.type = None  # 'reg' | 'mem' | 'imm'
        self.size = 0
        self.reg = self.base = self.index = None
        self.disp = 0
        self.scale = 0
        self.write = False
        self.imm = 0

    def has_disp(self):
        return self.disp != 0


NONE_OP = Op()


class Ins:
    __slots__ = ("ip", "len", "mn", "ops", "rel", "opcode", "modrm", "text")

    def op(self, i):
        return self.ops[i] if i < len(self.ops) else NONE_OP


def to_ins(ci):
    ins = Ins()
    ins.ip, ins.len = ci.address, ci.size
    ins.mn = MNEM_ALIAS.get(ci.id, ci.id)
    ins.opcode = ci.opcode[0]
    ins.modrm = ci.modrm
    ins.text = "%s %s" % (ci.mnemonic, ci.op_str)
    ops = []
    rel = False
    for o in ci.operands:
        p = Op()
        p.size = o.size * 8
        p.write = bool(o.access & capstone.CS_AC_WRITE)
        if o.type == X.X86_OP_REG:
            p.type, p.reg = "reg", ci.reg_name(o.reg)
        elif o.type == X.X86_OP_MEM:
            p.type = "mem"
            p.base = ci.reg_name(o.mem.base) if o.mem.base else None
            p.index = ci.reg_name(o.mem.index) if o.mem.index else None
            p.disp = o.mem.disp
            p.scale = o.mem.scale if p.index else 0
            if p.base == "rip":
                rel = True
        elif o.type == X.X86_OP_IMM:
            p.type, p.imm = "imm", o.imm
        ops.append(p)
    if any(ci.group(g) for g in REL_BRANCH_GROUPS) and ops and ops[0].type == "imm":
        rel = True
    if not ops and ins.mn in SIGNEXT_HIDDEN:
        p = Op()
        p.type, p.reg, p.size, p.write = "reg", SIGNEXT_HIDDEN[ins.mn], 64, True
        ops.append(p)
    ins.ops = ops
    ins.rel = rel
    return ins


_dcache = {}


def decode(m, ip):
    k = (id(m), ip)
    if k in _dcache:
        return _dcache[k]
    code = m.read(ip, 15)
    r = None
    if code:
        ci = next(MD.disasm(code, ip, 1), None)
        if ci is not None:
            r = to_ins(ci)
    _dcache[k] = r
    return r


def scan_instructions(m, start, end, cb):
    """ZydisUtility::ScanInstructions: linear decode, break on decode failure or cb() == True."""
    ip = start
    while ip < end:
        ins = decode(m, ip)
        if ins is None:
            break
        if cb(ip, ins, ins.op):
            break
        ip += ins.len


def abs_addr(ins, op):
    """ZydisCalcAbsoluteAddress."""
    if op.type == "imm":
        return op.imm if ins.rel else None  # capstone already reports the absolute branch target
    if op.type == "mem":
        if op.base == "rip":
            return (ins.ip + ins.len + op.disp) & 0xFFFFFFFFFFFFFFFF
        if op.base is None and op.index is None:
            return op.disp & 0xFFFFFFFFFFFFFFFF
    return None


def get_absolute_address(ins, op):
    a = abs_addr(ins, op)
    return a if a is not None else 0


def resolve_call_target(m, ins, op):
    raw = abs_addr(ins, op(0))
    if raw is None:
        return 0
    if ins.opcode == 0xFF and op(0).type == "mem":
        v = m.u64(raw)
        return v or 0
    if ins.opcode == 0xE8:
        cur = raw
        for _ in range(3):
            p = decode(m, cur)
            if p is None:
                break
            if p.mn == X.X86_INS_JMP and p.modrm == 0x25 and p.op(0).type == "mem":
                got = abs_addr(p, p.op(0))
                if got is not None:
                    return m.u64(got) or 0
            if p.mn in (X.X86_INS_RET, X.X86_INS_INT3):
                break
            cur += p.len
        return raw
    return 0


# ------------------------------------------------------------------ address_resolve.h
class ResolveVote:
    def __init__(self):
        self.values = []
        self.unique = False

    def add(self, value, unique=False):
        if value == -1:
            return
        self.unique |= unique
        for pair in self.values:
            if pair[0] == value:
                pair[1] += 1
                return
        self.values.append([value, 1])

    def empty(self):
        return not self.values

    def ambiguous(self):
        return len(self.values) > 1

    def value(self):
        return self.values[0][0] if len(self.values) == 1 else -1

    def corroborated(self):
        return len(self.values) == 1 and (self.unique or self.values[0][1] >= 2)

    def describe(self):
        return ", ".join("%d(x%d)" % (v, n) for v, n in self.values)


def vote_candidates(vote, cands):
    if len(cands) == 1:
        vote.add(cands[0], True)
    else:
        for v in cands:
            vote.add(v)


# ------------------------------------------------------------------ the port
class Resolver:
    def __init__(self, plat, gamedata):
        self.plat = plat
        self.m = audit.module("engine", plat, "new")
        self.this = "rdi" if plat == "linux" else "rcx"
        self.gd = dict(gamedata)  # g_pGameData offsets (mutable, like OverwriteOffset)
        self.gd_orig = dict(gamedata)
        self.out = {}
        self.log = []

    # --- helpers
    def rva(self, a):
        return hex(self.m.rva(a)) if a else None

    def is_volatile(self, r):
        b = base_reg(r)
        if b in VOLATILE_COMMON:
            return True
        return self.plat == "linux" and b in ("rdi", "rsi")

    @staticmethod
    def is_object_base(r):
        b = base_reg(r)
        return b is not None and b not in ("rsp", "rbp", "rip")

    @staticmethod
    def is_field_mem(op, expected):
        return (op.type == "mem" and base_reg(op.base) == expected and op.index is None
                and op.has_disp() and op.disp > 0)

    def is_any_this_mem(self, op, saved):
        return self.is_field_mem(op, self.this) or (saved is not None and self.is_field_mem(op, saved))

    def frange(self, a):
        return self.m.func_range(a)

    def find_string(self, s, read_only=False, exact=False):
        return self.m.find_string(s, read_only=read_only, exact=exact)

    def refs(self, a):
        return self.m.refs_to(a) if a else []

    def find_all_funcs_from_strings(self, strs):
        sets = []
        for s in strs:
            a = self.find_string(s, False, True)
            if not a:
                return []
            r = self.refs(a)
            if not r:
                return []
            sets.append(r)
        return self.m.intersect(sets)

    def find_func_from_string(self, s):
        r = self.find_all_funcs_from_strings([s])
        self.log.append("FindFunctionFromStringRef(%r) -> %s" % (s, [self.rva(x) for x in r]))
        return r[0] if len(r) == 1 else 0

    def anchor_vfuncs(self, vfuncs, s):
        refs = self.refs(s)
        out = []
        for v in vfuncs:
            r = self.frange(v)
            if r is None:
                continue
            if any(r[0] < x < r[1] for x in refs) and all(o[0] != r[0] for o in out):
                out.append(r)
        return out

    def anchor_functions(self, s):
        out = []
        for x in self.refs(s):
            r = self.frange(x)
            if r is None:
                continue
            if all(o[0] != r[0] for o in out):
                out.append(r)
        return out

    def find_vfunc_anchors(self, vfuncs, s, exact=False):
        a = self.find_string(s, False, exact)
        anchors = self.anchor_vfuncs(vfuncs, a) if a else []
        self.log.append("anchor %r exact=%s str=%s refs=%s anchors=%s" % (
            s, exact, self.rva(a), [self.rva(x) for x in self.refs(a)], [self.rva(r[0]) for r in anchors]))
        return a, anchors

    def scan_with_this(self, rng, cb):
        st = {"saved": None}

        def inner(ip, ins, op):
            if (st["saved"] is None and ins.mn == X.X86_INS_MOV and op(0).type == "reg" and op(1).type == "reg"
                    and base_reg(op(1).reg) == self.this and not self.is_volatile(op(0).reg)):
                st["saved"] = base_reg(op(0).reg)
            return cb(ip, ins, op, st["saved"])
        scan_instructions(self.m, rng[0], rng[1], inner)

    def scan_with_leaves(self, start, end, max_leaf, cb):
        st = {"found": False}

        def p1(ip, ins, op):
            st["found"] = cb(ip, ins, op)
            return st["found"]
        scan_instructions(self.m, start, end, p1)
        if st["found"]:
            return True

        def p2(ip, ins, op):
            if ins.mn != X.X86_INS_CALL or not ins.rel:
                return False
            t = resolve_call_target(self.m, ins, op)
            if t == 0:
                return False
            leaf = self.frange(t)
            if leaf is None or leaf[1] - leaf[0] > max_leaf:
                return False

            def lcb(lip, lins, lop):
                st["found"] = cb(lip, lins, lop)
                return st["found"]
            scan_instructions(self.m, leaf[0], leaf[1], lcb)
            return st["found"]
        scan_instructions(self.m, start, end, p2)
        return st["found"]

    def find_utl_vectors(self, start, end, elem, max_pair_gap=8):
        K = 16
        res = []
        s = dict(size_base=None, size_disp=0, size_ttl=0, mem_reg=None, mem_disp=0, mem_ttl=0)

        def commit(d):
            if d not in res:
                res.append(d)

        def cb(ip, ins, op):
            if s["size_ttl"] > 0:
                s["size_ttl"] -= 1
            if s["mem_reg"] is not None and ins.mn != X.X86_INS_NOP:
                ttl = s["mem_ttl"]
                s["mem_ttl"] -= 1
                if ttl <= 0:
                    s["mem_reg"] = None
                elif (ins.mn == X.X86_INS_ADD and op(0).type == "reg" and base_reg(op(0).reg) == s["mem_reg"]
                      and op(1).type == "imm" and op(1).imm == elem):
                    commit(s["mem_disp"])
                    s["mem_reg"] = None
                else:
                    for o in ins.ops:
                        if o.type == "mem" and o.index is not None and base_reg(o.base) == s["mem_reg"]:
                            if o.scale == elem:
                                commit(s["mem_disp"])
                            s["mem_reg"] = None
                            break
                        if o.type == "reg" and o.write and base_reg(o.reg) == s["mem_reg"]:
                            s["mem_reg"] = None
                            break
            o1 = op(1)
            if (ins.mn != X.X86_INS_MOV or op(0).type != "reg" or o1.type != "mem" or o1.index is not None
                    or not o1.has_disp() or o1.disp <= 0 or not self.is_object_base(o1.base)):
                return False
            b = base_reg(o1.base)
            if o1.size == 32:
                s["size_base"], s["size_disp"], s["size_ttl"] = b, o1.disp, max_pair_gap
            elif o1.size == 64 and s["size_ttl"] > 0 and b == s["size_base"] and o1.disp == s["size_disp"] + 8:
                s["mem_reg"], s["mem_disp"], s["mem_ttl"] = base_reg(op(0).reg), s["size_disp"], K
                s["size_base"] = None
            return False
        scan_instructions(self.m, start, end, cb)
        return res

    def leaf_field_getter(self, func, size=32, max_size=0x10):
        r = self.frange(func)
        if r is None or r[1] - r[0] > max_size:
            return -1
        st = {"disp": -1, "i": 0}

        def cb(ip, ins, op):
            if ins.mn == X.X86_INS_ENDBR64:
                return False
            i = st["i"]
            st["i"] += 1
            if i == 0:
                if (ins.mn == X.X86_INS_MOV and op(0).type == "reg" and base_reg(op(0).reg) == "rax"
                        and op(1).size == size and self.is_field_mem(op(1), self.this)):
                    st["disp"] = op(1).disp
                    return False
                return True
            if ins.mn != X.X86_INS_RET:
                st["disp"] = -1
            return True
        scan_instructions(self.m, r[0], r[1], cb)
        return st["disp"]

    def try_overwrite(self, name, vote, note=""):
        cur = self.gd.get(name)
        rec = dict(votes=vote.describe(), corroborated=vote.corroborated(), resolved=vote.value(),
                   gamedata=self.gd_orig.get(name), note=note)
        if vote.empty():
            rec["action"] = "failed (kept gamedata)"
        elif vote.ambiguous():
            rec["action"] = "ambiguous (kept gamedata)"
        else:
            v = vote.value()
            if cur is not None and cur != v:
                if not vote.corroborated():
                    rec["action"] = "MISMATCH uncorroborated (kept gamedata)"
                else:
                    rec["action"] = "MISMATCH corroborated (OVERWRITTEN)"
                    self.gd[name] = v
            else:
                rec["action"] = "match" if cur == v else "set"
                self.gd[name] = v
        rec["effective"] = self.gd.get(name)
        self.out[name] = rec

    # ---------------------------------------------------------------- CServerSideClient
    def resolve_ssc(self):
        m = self.m
        vf_base = m.vfuncs("CServerSideClientBase")
        vf = m.vfuncs("CServerSideClient")
        self.log.append("vtables: CServerSideClientBase=%d CServerSideClient=%d entries" % (len(vf_base), len(vf)))
        this = self.this

        def find_deref_fields(rng):
            res = []
            st = dict(reg=None, off=-1, ttl=0)

            def cb(ip, ins, op, saved):
                if st["reg"] is not None:
                    o1 = op(1)
                    if (ins.mn == X.X86_INS_MOV and op(0).type == "reg" and o1.type == "mem" and o1.size == 64
                            and o1.index is None and o1.disp == 0 and base_reg(o1.base) == st["reg"]):
                        if st["off"] not in res:
                            res.append(st["off"])
                        st["reg"] = None
                    else:
                        st["ttl"] -= 1
                        if (st["ttl"] <= 0 or ins.mn == X.X86_INS_CALL
                                or (op(0).type == "reg" and op(0).write and base_reg(op(0).reg) == st["reg"])):
                            st["reg"] = None
                if (ins.mn == X.X86_INS_MOV and op(0).type == "reg" and op(1).size == 64
                        and self.is_any_this_mem(op(1), saved)):
                    st["reg"], st["off"], st["ttl"] = base_reg(op(0).reg), op(1).disp, 8
                return False
            self.scan_with_this(rng, cb)
            return res

        # --- m_NetChannel, m_Name, m_UserId
        s, anchors = self.find_vfunc_anchors(vf, "Client %d '%s' setting rate to %d\n")
        net, name, uid = ResolveVote(), ResolveVote(), ResolveVote()
        det = []
        for rng in anchors:
            d = find_deref_fields(rng)
            vote_candidates(net, d)
            st = dict(lq=-1, lw=-1, name=-1, uid=-1)

            def cb(ip, ins, op, saved):
                if saved is None:
                    return False
                if (ins.mn == X.X86_INS_MOV and op(0).type == "reg" and op(1).size == 64
                        and self.is_field_mem(op(1), saved) and op(1).disp != net.value()):
                    st["lq"] = op(1).disp
                if (ins.mn == X.X86_INS_MOVZX and op(0).type == "reg" and op(1).size == 16
                        and self.is_field_mem(op(1), saved)):
                    st["lw"] = op(1).disp
                if ins.mn == X.X86_INS_LEA and ins.rel and get_absolute_address(ins, op(1)) == s:
                    st["name"], st["uid"] = st["lq"], st["lw"]
                    return True
                return False
            self.scan_with_this(rng, cb)
            name.add(st["name"])
            uid.add(st["uid"])
            det.append("%s: deref=%s name=%d userid=%d" % (self.rva(rng[0]), d, st["name"], st["uid"]))
        self.try_overwrite("CServerSideClient::m_NetChannel", net, "; ".join(det))
        self.try_overwrite("CServerSideClient::m_Name", name, "; ".join(det))
        self.try_overwrite("CServerSideClient::m_UserId", uid, "; ".join(det))

        # --- m_SteamId, m_ConVars, m_Slot
        s, anchors = self.find_vfunc_anchors(vf, "userinfo", True)
        sid, cv, slot = ResolveVote(), ResolveVote(), ResolveVote()
        det = []
        for rng in anchors:
            st = dict(sid=-1, cv=-1, slot=-1, found=False)

            def cb(ip, ins, op, saved):
                if saved is None:
                    return False
                if not st["found"] and ins.mn == X.X86_INS_LEA and ins.rel and get_absolute_address(ins, op(1)) == s:
                    st["found"] = True
                if (ins.mn == X.X86_INS_MOV and op(0).size == 64 and op(1).type == "reg"
                        and self.is_any_this_mem(op(0), saved)):
                    d = op(0).disp
                    if not st["found"]:
                        if st["sid"] == -1:
                            st["sid"] = d
                    elif st["cv"] == -1:
                        st["cv"] = d
                if (ins.mn == X.X86_INS_MOV and op(0).type == "reg" and op(1).size == 32
                        and self.is_any_this_mem(op(1), saved)):
                    st["slot"] = op(1).disp
                return False
            self.scan_with_this(rng, cb)
            sid.add(st["sid"]); cv.add(st["cv"]); slot.add(st["slot"])
            det.append("%s: steamid=%d convars=%d slot=%d" % (self.rva(rng[0]), st["sid"], st["cv"], st["slot"]))
        self.try_overwrite("CServerSideClient::m_SteamId", sid, "; ".join(det))
        self.try_overwrite("CServerSideClient::m_ConVars", cv, "; ".join(det))
        self.try_overwrite("CServerSideClient::m_Slot", slot, "; ".join(det))

        # --- m_SignonState
        s, anchors = self.find_vfunc_anchors(vf, "Too many move messages")
        sig = ResolveVote()
        det = []
        for rng in anchors:
            st = dict(off=-1, where=None)

            def cb(ip, ins, op):
                o0, o1 = op(0), op(1)
                if (ins.mn != X.X86_INS_CMP or o0.size != 32 or o1.type != "imm" or o1.imm != 6
                        or not self.is_field_mem(o0, this)):
                    st["off"] = -1
                    return False
                st["off"], st["where"] = o0.disp, ip
                return True
            self.scan_with_leaves(rng[0], rng[1], 0x10, cb)
            sig.add(st["off"])
            det.append("%s: signon=%d at %s" % (self.rva(rng[0]), st["off"], self.rva(st["where"])))
        self.try_overwrite("CServerSideClient::m_SignonState", sig, "; ".join(det))

        # --- m_IsHLTV
        s, anchors = self.find_vfunc_anchors(vf, "TV client has no downstream TV sink\n")
        hv = ResolveVote()
        det = []
        for rng in anchors:
            st = dict(off=-1, where=None)

            def cb(ip, ins, op, saved):
                if ins.mn == X.X86_INS_CMP and op(0).size == 8 and self.is_any_this_mem(op(0), saved):
                    st["off"], st["where"] = op(0).disp, ip
                    return True
                return False
            self.scan_with_this(rng, cb)
            hv.add(st["off"])
            det.append("%s: ishltv=%d at %s" % (self.rva(rng[0]), st["off"], self.rva(st["where"])))
        self.try_overwrite("CServerSideClient::m_IsHLTV", hv, "; ".join(det))

        # --- m_FullyAuthenticated
        f = self.find_func_from_string("SV: OnValidateAuthTicketResponse duplicate authentication")
        if f:
            rng = self.frange(f)
            fa = ResolveVote()
            cands = []
            if rng is not None:
                def cb(ip, ins, op):
                    o0, o1 = op(0), op(1)
                    if (ins.mn == X.X86_INS_MOV and o0.type == "mem" and o0.size == 8 and o0.index is None
                            and o0.has_disp() and o0.disp > 0 and o1.type == "imm" and o1.imm == 1
                            and self.is_object_base(o0.base)):
                        if o0.disp not in cands:
                            cands.append(o0.disp)
                    return False
                scan_instructions(m, rng[0], rng[1], cb)
                vote_candidates(fa, cands)
            self.try_overwrite("CServerSideClient::m_FullyAuthenticated", fa,
                               "func %s range %s candidates=%s" % (self.rva(f), rng and [self.rva(x) for x in rng], cands))
        else:
            self.out["CServerSideClient::m_FullyAuthenticated"] = dict(action="block skipped (anchor function not unique/found)",
                                                                       gamedata=self.gd_orig.get("CServerSideClient::m_FullyAuthenticated"),
                                                                       effective=self.gd.get("CServerSideClient::m_FullyAuthenticated"), resolved=-1, votes="", corroborated=False, note="")

        # --- m_vecLoadedSpawnGroups
        s = self.find_string("%s:  Not sending unload group to client '%s' due to not being sent\n", True, False)
        anchors = self.anchor_functions(s) if s else []
        sg = ResolveVote()
        det = []
        for rng in anchors:
            c = self.find_utl_vectors(rng[0], rng[1], 4)
            vote_candidates(sg, c)
            det.append("%s: %s" % (self.rva(rng[0]), c))
        self.try_overwrite("CServerSideClient::m_vecLoadedSpawnGroups", sg, "str %s; " % self.rva(s) + "; ".join(det))

        # --- m_nDeltaTick, m_FakeClient
        f = self.find_func_from_string("'%s' already awaiting full update\n")
        if f:
            rng = self.frange(f)
            st = dict(dt=-1, fc=-1, vcall=-1, fc_how=None, dt_at=None)
            if rng is not None:
                def cb(ip, ins, op, saved):
                    if (st["dt"] == -1 and ins.mn == X.X86_INS_MOV and op(0).size == 32 and op(1).type == "reg"
                            and self.is_any_this_mem(op(0), saved)):
                        st["dt"], st["dt_at"] = op(0).disp, ip
                        return True
                    o0 = op(0)
                    if (st["vcall"] == -1 and ins.mn == X.X86_INS_CALL and o0.type == "mem" and o0.has_disp()
                            and o0.disp > 0 and o0.index is None and base_reg(o0.base) != "rip"):
                        st["vcall"] = o0.disp
                    return False
                self.scan_with_this(rng, cb)
                if st["vcall"] != -1:
                    idx = st["vcall"] // 8
                    if 0 <= idx < len(vf_base):
                        fn = vf_base[idx]
                        fr = self.frange(fn)
                        end = fr[1] if fr else fn + 32

                        def cb2(ip, ins, op):
                            o1 = op(1)
                            if (ins.mn == X.X86_INS_MOVZX and op(0).type == "reg" and o1.type == "mem" and o1.size == 8
                                    and o1.index is None and o1.has_disp() and o1.disp > 0):
                                st["fc"] = o1.disp
                                st["fc_how"] = "vcall +%#x -> CServerSideClientBase[%d] %s" % (st["vcall"], idx, self.rva(fn))
                                return True
                            return ins.mn in (X.X86_INS_RET, X.X86_INS_INT3)
                        scan_instructions(m, fn, end, cb2)
                    else:
                        st["fc_how"] = "vcall +%#x index %d outside CServerSideClientBase (%d entries)" % (st["vcall"], idx, len(vf_base))
                if st["fc"] == -1:
                    def cb3(ip, ins, op, saved):
                        if ins.mn == X.X86_INS_MOVZX and op(0).type == "reg" and op(1).size == 8 and self.is_any_this_mem(op(1), saved):
                            st["fc"] = op(1).disp
                            st["fc_how"] = (st["fc_how"] or "no vcall") + "; fallback inline movzx at %s" % self.rva(ip)
                            return True
                        return False
                    self.scan_with_this(rng, cb3)
            dt, fc = ResolveVote(), ResolveVote()
            dt.add(st["dt"]); fc.add(st["fc"])
            self.try_overwrite("CServerSideClient::m_nDeltaTick", dt, "func %s store at %s" % (self.rva(f), self.rva(st["dt_at"])))
            self.try_overwrite("CServerSideClient::m_FakeClient", fc, "func %s %s" % (self.rva(f), st["fc_how"]))

        # --- m_ControllerEntityIndex, m_GameServer
        spf = self.find_func_from_string("CServerSideClientBase::SpawnPlayer")
        spr = self.frange(spf) if spf else None
        if spr is not None:
            st = dict(ce=-1, gs=-1, caller=None, callers=[])
            slot_off = self.gd.get("CServerSideClient::m_Slot", 0)
            for i, v in enumerate(vf):
                rng = self.frange(v)
                if rng is None:
                    continue
                cs = {"hit": False}

                def cb(ip, ins, op):
                    if ins.mn in (X.X86_INS_CALL, X.X86_INS_JMP) and ins.rel:
                        t = get_absolute_address(ins, op(0))
                        tr = self.frange(t)
                        if t == spr[0] or (tr and tr[0] <= spr[0] and tr[1] >= spr[1]):
                            cs["hit"] = True
                            return True
                    return False
                scan_instructions(m, rng[0], rng[1], cb)
                if not cs["hit"]:
                    continue
                st["callers"].append("[%d]%s" % (i, self.rva(v)))
                sl = {"reg": None}

                def cb2(ip, ins, op, saved):
                    if (st["gs"] == -1 and ins.mn == X.X86_INS_MOV and op(0).type == "reg" and op(1).size == 64
                            and self.is_any_this_mem(op(1), saved)):
                        st["gs"] = op(1).disp
                    if (ins.mn == X.X86_INS_MOV and op(0).type == "reg" and op(1).size == 32
                            and self.is_any_this_mem(op(1), saved) and op(1).disp == slot_off):
                        sl["reg"] = base_reg(op(0).reg)
                    if (sl["reg"] is not None and ins.mn == X.X86_INS_MOV and op(0).size == 32 and op(1).type == "reg"
                            and base_reg(op(1).reg) == sl["reg"] and self.is_any_this_mem(op(0), saved)
                            and op(0).disp != slot_off):
                        st["ce"] = op(0).disp
                        st["caller"] = "[%d]%s store at %s" % (i, self.rva(v), self.rva(ip))
                        return True
                    return False
                self.scan_with_this(rng, cb2)
                if st["ce"] != -1:
                    break
            ce, gs = ResolveVote(), ResolveVote()
            ce.add(st["ce"], True)
            gs.add(st["gs"])
            note = "SpawnPlayer %s; callers %s; slot_off=%d; %s" % (self.rva(spf), st["callers"], slot_off, st["caller"])
            self.try_overwrite("CServerSideClient::m_GameServer", gs, note)
            self.try_overwrite("CServerSideClient::m_ControllerEntityIndex", ce, note)
        else:
            for k in ("CServerSideClient::m_GameServer", "CServerSideClient::m_ControllerEntityIndex"):
                self.out[k] = dict(action="block skipped (SpawnPlayer not found)", gamedata=self.gd_orig.get(k),
                                   effective=self.gd.get(k), resolved=-1, votes="", corroborated=False, note="")

        # --- m_PerfectWorld
        st = dict(pw=-1, getters=[])

        def scan_trivial(vfl, tag):
            for i, v in enumerate(vfl):
                r = self.frange(v)
                end = r[1] if r else v + 16
                c = dict(cand=-1, triv=False, n=0)

                def cb(ip, ins, op):
                    c["n"] += 1
                    o1 = op(1)
                    if (c["n"] == 1 and ins.mn == X.X86_INS_MOVZX and op(0).type == "reg" and o1.type == "mem"
                            and o1.size == 8 and o1.index is None and o1.has_disp() and o1.disp > 0):
                        c["cand"] = o1.disp
                        return False
                    if c["n"] == 2 and c["cand"] != -1 and ins.mn == X.X86_INS_RET:
                        c["triv"] = True
                    return True
                scan_instructions(m, v, end, cb)
                if c["triv"]:
                    st["getters"].append("%s[%d]=%d" % (tag, i, c["cand"]))
                if c["triv"] and c["cand"] > st["pw"]:
                    st["pw"] = c["cand"]
        scan_trivial(vf_base, "Base")
        scan_trivial(vf, "SSC")
        pw = ResolveVote()
        pw.add(st["pw"], True)
        self.try_overwrite("CServerSideClient::m_PerfectWorld", pw, "trivial byte getters: " + ", ".join(st["getters"]))

    # ---------------------------------------------------------------- CNetworkGameServer
    def resolve_ngs(self):
        m = self.m
        # m_ServerState
        f = self.find_func_from_string("Paused: %s")
        if f:
            rng = self.frange(f)
            v = ResolveVote()
            st = dict(off=-1, at=None)
            if rng is not None:
                def cb(ip, ins, op):
                    o0 = op(0)
                    if (ins.mn == X.X86_INS_CMP and o0.type == "mem" and o0.size == 32 and o0.index is None
                            and o0.has_disp() and o0.disp > 0 and op(1).type == "imm"):
                        st["off"], st["at"] = o0.disp, ip
                        return True
                    return False
                scan_instructions(m, rng[0], rng[1], cb)
                v.add(st["off"])
            self.try_overwrite("CNetworkGameServer::m_ServerState", v, "func %s cmp at %s" % (self.rva(f), self.rva(st["at"])))

        # m_vecClients
        s = self.find_string("<slot:userid:\"name\">\n", False, False)
        if s:
            refs = self.refs(s)
            rng = self.frange(refs[0]) if refs else None
            v = ResolveVote()
            how = "none"
            if rng is not None:
                st = {"at": None}

                def cb(ip, ins, op):
                    if ins.mn != X.X86_INS_CALL:
                        return False
                    t = resolve_call_target(m, ins, op)
                    if t == 0:
                        return False
                    d = self.leaf_field_getter(t)
                    if d != -1:
                        v.add(d, True)
                        st["at"] = "leaf getter %s called at %s" % (self.rva(t), self.rva(ip))
                        return True
                    return False
                scan_instructions(m, refs[0], rng[1], cb)
                how = st["at"]
            if v.empty() and rng is not None:
                c = self.find_utl_vectors(refs[0], rng[1], 8, 64)
                vote_candidates(v, c)
                how = "fallback FindUtlVectors(stride 8) -> %s" % c
            self.try_overwrite("CNetworkGameServer::m_vecClients", v,
                               "refs=%s func=%s; %s" % ([self.rva(x) for x in refs], rng and self.rva(rng[0]), how))

        # m_MapName
        s = self.find_string("map/mapname", False, True)
        if s:
            fl = self.find_all_funcs_from_strings(["map/mapname", "::ExecGameTypeCfg"])
            rng = self.frange(fl[0]) if fl and fl[0] > 0 else None
            st = dict(off=-1, last=-1, at=None)
            if rng is not None:
                def cb(ip, ins, op):
                    o1 = op(1)
                    if (ins.mn == X.X86_INS_MOV and op(0).type == "reg" and o1.type == "mem" and o1.size == 64
                            and o1.index is None and o1.has_disp() and o1.disp > 0):
                        b = base_reg(o1.base)
                        if b is not None and b not in ("rsp", "rbp", "rip"):
                            st["last"] = o1.disp
                    if ins.mn == X.X86_INS_LEA and ins.rel and get_absolute_address(ins, o1) == s:
                        st["off"], st["at"] = st["last"], ip
                        return True
                    return False
                scan_instructions(m, rng[0], rng[1], cb)
            v = ResolveVote()
            v.add(st["off"])
            self.try_overwrite("CNetworkGameServer::m_MapName", v,
                               "funcs=%s lea at %s" % ([self.rva(x) for x in fl], self.rva(st["at"])))


def load_gamedata(plat):
    p = r"C:\tmp\modsharp_update\msp_scratch\.asset\gamedata\engine.games.jsonc"
    j = jsonc.loads(open(p, encoding="utf-8").read())
    out = {}
    for k, e in (j.get("Offsets") or {}).items():
        if isinstance(e, dict) and plat in e:
            out[k] = e[plat]
    return out


def run(plat):
    gd = load_gamedata(plat)
    r = Resolver(plat, gd)
    r.resolve_ssc()
    r.resolve_ngs()
    return r


if __name__ == "__main__":
    which = sys.argv[1] if len(sys.argv) > 1 else "both"
    plats = ["windows", "linux"] if which == "both" else [which]
    allres = {}
    for p in plats:
        r = run(p)
        print("==== %s" % p)
        for l in r.log:
            print("  #", l)
        for k, v in r.out.items():
            print("  %-45s gd=%-5s res=%-5s votes=[%s] corr=%s -> %s | %s" % (
                k, v.get("gamedata"), v.get("resolved"), v.get("votes"), v.get("corroborated"), v.get("action"), v.get("note")))
        allres[p] = dict(out=r.out, log=r.log)
    if "--json" in sys.argv:
        json.dump(allres, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
