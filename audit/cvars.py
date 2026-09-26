"""Static approximation of the runtime cvar refs in FindFunctionFromReferences.

Runtime: ptr_to_cvar = FindPtr(ConVarData*) = &BaseConVar::m_ConVarData of the first static object
(lowest address) in the module that holds that ConVarData.  BaseConVar = { ConVarHandle m_Handle; ConVarData* m_ConVarData; }
so ptr_to_cvar = O + 8 and the handle is at O.
Static: O is found at each reference to the cvar name string: the first-argument register (rcx / rdi) at the
first call after the name reference, tracked through lea/mov inside the containing function.
"""
from capstone import x86 as X
import resolver

ARG0 = {"pe": X.X86_REG_RCX, "elf": X.X86_REG_RDI}


def _objects_for(m, name, log):
    a = m.find_string(name)
    if not a:
        log.append("cvar name string not found: %s" % name)
        return []
    objs = []
    for src in m.refs_to(a):
        fr = m.func_range(src)
        if not fr:
            continue
        regs = {}
        ip = fr[0]
        seen = False
        o = None
        while ip < fr[1]:
            ins = resolver.dec(m, ip)
            if ins is None:
                ip += 1
                continue
            ops = ins.operands
            if ins.id == X.X86_INS_LEA and ops[0].type == resolver.REG and ops[1].mem.base == X.X86_REG_RIP:
                regs[ops[0].reg] = ins.address + ins.size + ops[1].mem.disp
            elif ins.id == X.X86_INS_MOV and len(ops) == 2 and ops[0].type == resolver.REG and ops[1].type == resolver.REG:
                regs[ops[0].reg] = regs.get(ops[1].reg)
            elif ins.id == X.X86_INS_CALL:
                if seen:
                    o = regs.get(ARG0[m.kind])
                    break
                for r in (X.X86_REG_RAX, X.X86_REG_RCX, X.X86_REG_RDX, X.X86_REG_R8, X.X86_REG_R9, X.X86_REG_R10, X.X86_REG_R11,
                          X.X86_REG_RSI, X.X86_REG_RDI):
                    regs.pop(r, None)
            elif ops and ops[0].type == resolver.REG:
                regs.pop(ops[0].reg, None)
            if ip == src:
                seen = True
            ip += ins.size
        if o is not None:
            s = m.seg_of(o)
            if s is not None and s.w:
                objs.append(o)
    return sorted(set(objs))


def hook(m, cvars, log):
    sets = []
    for cv in cvars:
        cv = cv.strip()
        if not cv:
            continue
        sp = cv.rfind(" ")
        name, suffix = (cv, "") if sp < 0 else (cv[:sp].strip(), cv[sp + 1:])
        objs = _objects_for(m, name, log)
        if not objs:
            log.append("cvar object not found statically: %s" % name)
            return None
        o = objs[0]
        log.append("cvar %s object=%#x (of %d)" % (name, m.rva(o), len(objs)))
        ptr = o + 8
        add_ptr = add_handle = False
        if not suffix:
            add_ptr = True
        else:
            add_ptr = suffix in ("[ptr]", "[*]", "[both]")
            add_handle = suffix in ("[handle]", "[*]", "[both]")
            if not add_ptr and not add_handle:
                add_ptr = True
        merged = []
        if add_ptr:
            merged += m.refs_to(ptr)
        if add_handle:
            for src in m.refs_to(ptr - 8):
                found = False
                for cur in range(src - 64, src + 64):
                    ins = resolver.dec(m, cur)
                    if ins is None or ins.id != X.X86_INS_MOV or len(ins.operands) < 2:
                        continue
                    d, s_ = ins.operands[0], ins.operands[1]
                    if d.type == resolver.REG and d.reg in (X.X86_REG_EDX, X.X86_REG_ESI) and s_.type == resolver.IMM and (s_.imm & 0xFFFFFFFF) == 0xFFFFFFFF:
                        found = True
                        break
                if found:
                    merged.append(src)
        if not merged:
            log.append("Cvar %s has no references in code" % name)
            return "FAILED"
        sets.append(merged)
    return sets
