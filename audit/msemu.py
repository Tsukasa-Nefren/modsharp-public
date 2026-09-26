"""Static emulation of ModSharp's gamedata resolution (Engine/src/gamedata.cpp, module*.cpp).

Addresses are image VAs: PE -> ImageBase + RVA, ELF -> p_vaddr (base 0).
Approximations are marked with 'APPROX'.
"""
import os, re, struct, bisect, pickle, hashlib
import numpy as np
import capstone
from capstone import x86 as X

MAXLEN = 15
G_JUMP, G_CALL, G_RET, G_INT, G_IRET, G_BRREL = 1, 2, 3, 4, 5, 7
EXT_BASE = 0x7F0000000000  # sentinel for unresolved external symbols (ELF)


def new_md(detail=True):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = detail
    return md


class Seg:
    __slots__ = ("addr", "size", "x", "w", "data", "name")

    def __init__(s, addr, size, x, w, data, name=""):
        s.addr, s.size, s.x, s.w, s.data, s.name = addr, size, x, w, data, name

    def __contains__(s, a):
        return s.addr <= a < s.addr + s.size


# ---------------------------------------------------------------- loading
def load(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:2] == b"MZ":
        return _load_pe(path, raw)
    return _load_elf(path, raw)


def _load_pe(path, raw):
    import pefile
    pe = pefile.PE(data=raw, fast_load=True)
    m = Module(path, "pe")
    m.base = pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        va = m.base + s.VirtualAddress
        size = s.Misc_VirtualSize
        d = bytearray(size)
        rd = raw[s.PointerToRawData:s.PointerToRawData + min(size, s.SizeOfRawData)]
        d[:len(rd)] = rd
        ch = s.Characteristics
        m.segs.append(Seg(va, size, bool(ch & 0x20000000), bool(ch & 0x80000000), bytes(d),
                          s.Name.rstrip(b"\0").decode(errors="replace")))
    exc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    m.pdata = (exc.VirtualAddress, exc.Size)
    # exports
    pe.parse_data_directories(directories=[0])
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.name:
                m.exports[e.name.decode()] = m.base + e.address
    m.pe = pe
    return m


def _load_elf(path, raw):
    from elftools.elf.elffile import ELFFile
    import io
    e = ELFFile(io.BytesIO(raw))
    m = Module(path, "elf")
    m.base = 0
    loads = []
    for ph in e.iter_segments():
        t = ph["p_type"]
        if t == "PT_GNU_EH_FRAME":
            m.eh_frame_hdr = ph["p_vaddr"]
        if t != "PT_LOAD":
            continue
        img = bytearray(ph["p_memsz"])
        fs = ph["p_filesz"]
        img[:fs] = raw[ph["p_offset"]:ph["p_offset"] + fs]
        loads.append([ph["p_vaddr"], ph["p_memsz"], ph["p_flags"], img])
    # exec ranges from sections (GetElfExecutableRanges)
    xr = []
    for s in e.iter_sections():
        if s["sh_flags"] & 4 and s["sh_addr"] and s["sh_size"]:
            xr.append((s["sh_addr"], s["sh_addr"] + s["sh_size"]))
    xr.sort()
    merged = []
    for a, b in xr:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    # relocations
    dynsym = e.get_section_by_name(".dynsym")
    syms = list(dynsym.iter_symbols())
    m.dynsyms = syms

    def img_of(addr):
        for L in loads:
            if L[0] <= addr < L[0] + L[1]:
                return L
        return None
    for sec in e.iter_sections():
        if sec["sh_type"] not in ("SHT_RELA",):
            continue
        d = sec.data()
        arr = np.frombuffer(d, dtype=np.dtype([("off", "<u8"), ("info", "<u8"), ("add", "<i8")]))
        typ = (arr["info"] & 0xFFFFFFFF).astype(np.int64)
        sym = (arr["info"] >> 32).astype(np.int64)
        for L in loads:
            lo, hi = L[0], L[0] + L[1]
            sel = (arr["off"] >= lo) & (arr["off"] < hi - 7)
            if not sel.any():
                continue
            view = np.frombuffer(L[3], dtype="<u8", count=(len(L[3]) - (len(L[3]) % 8)) // 8) if False else None
            offs = arr["off"][sel].astype(np.int64) - lo
            t = typ[sel]
            s_ = sym[sel]
            a_ = arr["add"][sel]
            vals = np.zeros(len(offs), dtype=np.uint64)
            rel = t == 8
            vals[rel] = a_[rel].astype(np.uint64)
            other = np.nonzero((t == 1) | (t == 6) | (t == 7))[0]
            for i in other:
                sy = syms[int(s_[i])]
                if sy["st_shndx"] != "SHN_UNDEF":
                    v = sy["st_value"] + int(a_[i])
                else:
                    v = EXT_BASE + int(s_[i]) * 0x1000 + int(a_[i])
                vals[i] = v & 0xFFFFFFFFFFFFFFFF
            keep = rel | (t == 1) | (t == 6) | (t == 7)
            buf = L[3]
            for o, v in zip(offs[keep].tolist(), vals[keep].tolist()):
                buf[o:o + 8] = struct.pack("<Q", v)
    for vaddr, memsz, flags, img in loads:
        w = bool(flags & 2)
        if flags & 1 and merged:
            cur = vaddr
            end = vaddr + memsz
            app = False
            for a, b in merged:
                os_, oe = max(vaddr, a), min(end, b)
                if os_ >= oe:
                    continue
                if os_ > cur:
                    m.segs.append(Seg(cur, os_ - cur, False, w, bytes(img[cur - vaddr:os_ - vaddr])))
                m.segs.append(Seg(os_, oe - os_, True, w, bytes(img[os_ - vaddr:oe - vaddr])))
                cur = oe
                app = True
            if app and end > cur:
                m.segs.append(Seg(cur, end - cur, False, w, bytes(img[cur - vaddr:])))
            if app:
                continue
        m.segs.append(Seg(vaddr, memsz, bool(flags & 1), w, bytes(img)))
    for sy in syms:
        if sy.name and sy["st_shndx"] != "SHN_UNDEF" and sy["st_other"]["visibility"] == "STV_DEFAULT":
            m.exports[sy.name] = sy["st_value"]
    m.ext_sym_index = {sy.name: i for i, sy in enumerate(syms) if sy["st_shndx"] == "SHN_UNDEF" and sy.name}
    return m


# ---------------------------------------------------------------- module
class Module:
    def __init__(self, path, kind):
        self.path, self.kind = path, kind
        self.segs = []
        self.exports = {}
        self.base = 0
        self.eh_frame_hdr = 0
        self._vt = None
        self.fstarts = None

    # --- memory
    def seg_of(self, a):
        for s in self.segs:
            if s.addr <= a < s.addr + s.size:
                return s
        return None

    def read(self, a, n):
        s = self.seg_of(a)
        if s is None:
            return None
        o = a - s.addr
        return s.data[o:o + n]

    def u64(self, a):
        b = self.read(a, 8)
        return struct.unpack("<Q", b)[0] if b and len(b) == 8 else None

    def u32(self, a):
        b = self.read(a, 4)
        return struct.unpack("<I", b)[0] if b and len(b) == 4 else None

    def i32(self, a):
        b = self.read(a, 4)
        return struct.unpack("<i", b)[0] if b and len(b) == 4 else None

    def is_exec(self, a):
        return any(s.x and s.addr <= a < s.addr + s.size for s in self.segs)

    def is_data(self, a):
        return any((not s.x) and s.addr <= a < s.addr + s.size for s in self.segs)

    def rva(self, a):
        return a - self.base

    # --- scans
    @staticmethod
    def pat_regex(sig):
        toks = sig.split()
        return b"".join(b"." if t in ("?", "??") else re.escape(bytes([int(t, 16)])) for t in toks)

    def find_pattern_multi(self, sig):
        rx = re.compile(b"(?=" + self.pat_regex(sig) + b")", re.S)
        out = []
        for s in self.segs:
            if not s.x:
                continue
            out += [s.addr + mm.start() for mm in rx.finditer(s.data)]
        return out

    def find_pattern_strict(self, sig):
        r = self.find_pattern_multi(sig)
        return r[0] if len(r) == 1 else 0, len(r)

    def find_string(self, st, read_only=False, exact=True):
        needle = st.encode("utf-8") + b"\0"
        for s in self.segs:
            if s.x or (read_only and s.w):
                continue
            d = s.data
            i = d.find(needle)
            while i >= 0:
                if not exact or i == 0 or d[i - 1] == 0:
                    return s.addr + i
                i = d.find(needle, i + 1)
        return 0

    def find_ptrs(self, val):
        out = []
        for s in self.segs:
            if s.x:
                continue
            n = len(s.data) // 8
            arr = np.frombuffer(s.data, dtype="<u8", count=n)
            idx = np.nonzero(arr == np.uint64(val))[0]
            out += [s.addr + int(i) * 8 for i in idx]
        return out

    # ---------------------------------------------------------- index (functions + references)
    def build_index(self, cache_dir, nproc=30):
        key = hashlib.sha1((os.path.realpath(self.path).lower() + str(os.path.getsize(self.path)) + str(os.path.getmtime(self.path)) + "v3").encode()).hexdigest()[:16]
        cp = os.path.join(cache_dir, os.path.basename(self.path) + "." + key + ".pkl")
        if os.path.exists(cp):
            with open(cp, "rb") as f:
                st = pickle.load(f)
            self.__dict__.update(st)
            return
        if self.kind == "pe":
            self._build_pe(nproc)
        else:
            self._build_elf(nproc)
        st = {k: getattr(self, k) for k in ("fstarts", "fends_known", "ref_t", "ref_s", "seed_list", "fde_ends", "ref_isj") if hasattr(self, k)}
        with open(cp, "wb") as f:
            pickle.dump(st, f)

    # ---- PE
    def _pe_pdata(self):
        rva, size = self.pdata
        n = size // 12
        d = self.read(self.base + rva, n * 12)
        arr = np.frombuffer(d, dtype="<u4").reshape(-1, 3)
        ents = []
        i = 0
        while i < n:
            b, e, u = (int(x) for x in arr[i])
            j = i + 1
            while j < n and int(arr[j][0]) == e:
                uw = self.read(self.base + int(arr[j][2]), 1)[0]
                if ((uw >> 3) & 0x4) == 0:  # UNW_FLAG_CHAININFO
                    break
                e = int(arr[j][1])
                j += 1
            ents.append((self.base + b, self.base + e))
            i = j
        ents.sort()
        return ents

    def _build_pe(self, nproc):
        from multiprocessing import Pool
        auth = self._pe_pdata()
        auth_starts = [a for a, _ in auth]
        auth_ends = [b for _, b in auth]
        self._auth = (auth_starts, auth_ends)

        def find_auth(a):
            i = bisect.bisect_right(auth_starts, a) - 1
            return i >= 0 and a < auth_ends[i]
        xsegs = [(s.addr, s.addr + s.size) for s in self.segs if s.x]

        def in_text(a):
            return any(lo <= a < hi for lo, hi in xsegs)
        supp = set()
        for s in self.segs:
            if s.name != ".rdata":
                continue
            arr = np.frombuffer(s.data, dtype="<u8", count=len(s.data) // 8)
            for lo, hi in xsegs:
                cand = arr[(arr >= lo) & (arr < hi)]
                for v in np.unique(cand).tolist():
                    if not find_auth(v):
                        supp.add(v)
        all_refs, all_jrefs = [], []
        scanned = set()
        ranges = list(auth)
        accepted = []
        rounds = 0
        with Pool(nproc, initializer=_winit, initargs=(self.path,)) as pool:
            supp_entries = self._pe_supp(sorted(supp), auth_starts)
            ranges = sorted(auth + supp_entries)
            while ranges and rounds < 64:
                chunks = [ranges[i::nproc] for i in range(nproc)]
                res = pool.map(_pe_decode, chunks)
                prev = len(supp)
                for refs, jrefs, cands in res:
                    all_refs.append(refs)
                    all_jrefs.append(jrefs)
                    for c in cands:
                        if in_text(c) and not find_auth(c):
                            supp.add(c)
                for r in ranges:
                    scanned.add(r)
                rounds += 1
                if len(supp) == prev:
                    break
                supp_entries = self._pe_supp(sorted(supp), auth_starts)
                ranges = [e for e in supp_entries if e not in scanned]
        fents = sorted(auth + supp_entries)
        self.fstarts = [a for a, _ in fents]
        self.fends_known = [b for _, b in fents]
        refs = np.concatenate(all_refs) if all_refs else np.zeros((0, 3), np.int64)
        jrefs = np.concatenate(all_jrefs) if all_jrefs else np.zeros((0, 3), np.int64)
        fs = np.array(self.fstarts, dtype=np.int64)
        fe = np.array(self.fends_known, dtype=np.int64)

        def valid(arr, is_jump):
            if len(arr) == 0:
                return arr
            rs = arr[:, 2]
            idx = np.searchsorted(fs, rs)
            ok = (idx < len(fs)) & (fs[np.minimum(idx, len(fs) - 1)] == rs)
            ok &= arr[:, 1] < fe[np.minimum(idx, len(fs) - 1)]
            if is_jump:
                t = arr[:, 0]
                ti = np.searchsorted(fs, t)
                isf = (ti < len(fs)) & (fs[np.minimum(ti, len(fs) - 1)] == t)
                ok &= isf & (t != rs)
            return arr[ok]
        allr = np.concatenate([valid(refs, False), valid(jrefs, True)])
        allr = np.unique(allr[:, :2], axis=0)
        order = np.lexsort((allr[:, 1], allr[:, 0]))
        allr = allr[order]
        self.ref_t = allr[:, 0].copy()
        self.ref_s = allr[:, 1].copy()
        self.seed_list = None
        self.fde_ends = None

    def _pe_supp(self, supp_starts, auth_starts):
        """build_supplemental_entries (APPROX: same algorithm, capstone instead of zydis)."""
        md = new_md()
        accepted = []
        result = []
        xsegs = [s for s in self.segs if s.x]
        for start in reversed(supp_starts):
            seg = next((s for s in xsegs if s.addr <= start < s.addr + s.size), None)
            if seg is None:
                continue
            hard_end = seg.addr + seg.size
            if hard_end - start > 100000:
                hard_end = start + 100000
            k = bisect.bisect_right(auth_starts, start)
            if k < len(auth_starts) and auth_starts[k] < hard_end:
                hard_end = auth_starts[k]
            if accepted and accepted[-1] < hard_end:
                hard_end = accepted[-1]
            end = _recover_end(self, md, start, hard_end, auth_starts, accepted)
            if end:
                result.append((start, end))
                accepted.append(start)
        result.sort()
        return result

    # ---- ELF
    def _build_elf(self, nproc):
        from multiprocessing import Pool
        xsegs = sorted([s for s in self.segs if s.x], key=lambda s: s.addr)
        dsegs = [s for s in self.segs if not s.x]
        # phase 1: data pointers to exec
        seeds = []
        for s in dsegs:
            arr = np.frombuffer(s.data, dtype="<u8", count=len(s.data) // 8)
            for xs in xsegs:
                seeds.append(arr[(arr >= xs.addr) & (arr < xs.addr + xs.size)].astype(np.int64))
        # phase 2
        chunks = []
        total = sum(s.size for s in xsegs)
        csize = max(1, (total + nproc * 4 - 1) // (nproc * 4))
        for s in xsegs:
            c = s.addr
            while c < s.addr + s.size:
                ce = min(c + csize, s.addr + s.size)
                chunks.append((s.addr, s.addr + s.size, c - min(24, c - s.addr), c, ce))
                c = ce
        with Pool(nproc, initializer=_winit, initargs=(self.path,)) as pool:
            res = pool.map(_elf_decode, chunks)
        refs = []
        jrefs = []
        for f, r, j in res:
            seeds.append(f)
            refs.append(r)
            jrefs.append(j)
        # FDE
        fde_starts, fde_ends = self._parse_eh()
        seeds.append(np.array(fde_starts, dtype=np.int64))
        seed_arr = np.unique(np.concatenate(seeds))
        self.seed_list = seed_arr
        self.fde_ends = fde_ends
        self.fstarts = None
        self.fends_known = {}
        refs = np.concatenate(refs) if refs else np.zeros((0, 2), np.int64)
        jrefs = np.concatenate(jrefs) if jrefs else np.zeros((0, 2), np.int64)
        # keep all raw; validity checked lazily (containing function must exist)
        self._raw_refs = refs
        self._raw_jrefs = jrefs
        allr = np.concatenate([refs, jrefs])
        order = np.lexsort((allr[:, 1], allr[:, 0]))
        allr = allr[order]
        isj = np.concatenate([np.zeros(len(refs), bool), np.ones(len(jrefs), bool)])[order]
        self.ref_t = allr[:, 0].copy()
        self.ref_s = allr[:, 1].copy()
        self.ref_isj = isj
        self.fstarts = "elf"

    def _parse_eh(self):
        hdr = self.eh_frame_hdr
        if not hdr:
            return [], {}
        b = self.read(hdr, 12)
        if b[0] != 1 or b[1] != 0x1B or b[2] != 0x03 or b[3] != 0x3B:
            return [], {}
        cnt = struct.unpack("<I", b[8:12])[0]
        tab = np.frombuffer(self.read(hdr + 12, cnt * 8), dtype="<i4").reshape(-1, 2)
        starts = []
        ends = {}
        for ir, fr in tab.tolist():
            pc = hdr + ir
            fa = hdr + fr
            if not self.is_exec(pc):
                continue
            fb = self.read(fa, 16)
            ln, cie, pbr, rng = struct.unpack("<IIiI", fb)
            if ln in (0, 0xFFFFFFFF) or cie == 0:
                continue
            if fa + 8 + pbr != pc:
                continue
            starts.append(pc)
            ends[pc] = max(ends.get(pc, 0), pc + rng)
        return sorted(set(starts)), ends

    # ---- function lookup
    def func_entry(self, ip):
        """GetFunctionEntry: start of the entry with greatest start <= ip if ip < end, else 0."""
        r = self.func_range(ip)
        return r[0] if r else 0

    def func_range(self, ip):
        if self.kind == "pe":
            i = bisect.bisect_right(self.fstarts, ip) - 1
            if i >= 0 and ip < self.fends_known[i]:
                return (self.fstarts[i], self.fends_known[i])
            return None
        sl = self.seed_list
        i = int(np.searchsorted(sl, ip, side="right")) - 1
        if i < 0:
            return None
        st = int(sl[i])
        end = self.elf_func_end(i)
        if end and ip < end:
            return (st, end)
        return None

    def is_known_function_entry(self, a):
        if self.kind == "pe":
            i = bisect.bisect_left(self.fstarts, a)
            return i < len(self.fstarts) and self.fstarts[i] == a
        sl = self.seed_list
        i = int(np.searchsorted(sl, a))
        return i < len(sl) and int(sl[i]) == a and self.elf_func_end(i) > a

    def elf_func_end(self, i):
        if i in self.fends_known:
            return self.fends_known[i]
        sl = self.seed_list
        start = int(sl[i])
        xs = next((s for s in self.segs if s.x and s.addr <= start < s.addr + s.size), None)
        if xs is None:
            self.fends_known[i] = 0
            return 0
        xend = xs.addr + xs.size
        nxt = int(sl[i + 1]) if i + 1 < len(sl) and int(sl[i + 1]) < xend else xend
        hard_end = min(nxt, start + 100000)
        end = _cfg_end(self, start, hard_end)
        if nxt == hard_end:
            ext = _find_last_real(self, nxt, end, xs.addr, xend)
            if ext > end:
                end = ext
        fe = self.fde_ends.get(start)
        if fe:
            fe = min(fe, hard_end)
            if fe > end:
                end = fe
        self.fends_known[i] = end if end > start else 0
        return self.fends_known[i]

    # ---- references
    def refs_to(self, target):
        lo = int(np.searchsorted(self.ref_t, target, side="left"))
        hi = int(np.searchsorted(self.ref_t, target, side="right"))
        out = []
        for k in range(lo, hi):
            s = int(self.ref_s[k])
            if self.kind == "elf":
                r = self.func_range(s)
                if r is None:
                    continue
                if self.ref_isj[k] and (target == r[0] or not self.is_known_function_entry(target)):
                    continue
            out.append(s)
        return out

    def intersect(self, ref_sets):
        ref_sets = sorted(ref_sets, key=len)
        def funcs(rs):
            return sorted(set(f for f in (self.func_entry(s) for s in rs) if f))
        cand = funcs(ref_sets[0])
        for rs in ref_sets[1:]:
            if not cand:
                break
            nf = set(funcs(rs))
            cand = [c for c in cand if c in nf]
        return cand

    # ---- vtables
    def vtables(self):
        if self._vt is not None:
            return self._vt
        vt = []
        if self.kind == "pe":
            tdname = self.find_string(".?AVtype_info@@", exact=False)
            ti_vt = self.u64(tdname - 0x10)
            valid = set(a - self.base for a in self.find_ptrs(ti_vt))
            for s in self.segs:
                if s.x or s.w:
                    continue
                arr = np.frombuffer(s.data, dtype="<u8", count=len(s.data) // 8)
                cand = np.nonzero(((arr & 3) == 0) & (arr >= s.addr) & (arr < s.addr + s.size))[0]
                for i in cand.tolist():
                    if i * 8 >= s.size - 8:
                        continue
                    col = int(arr[i])
                    sig, off, cdo, ptd = struct.unpack("<IIII", self.read(col, 16))
                    if sig != 1 or ptd not in valid:
                        continue
                    td = self.base + ptd
                    raw = self.read(td + 0x10, 512).split(b"\0")[0].decode(errors="replace")
                    vt.append(dict(addr=s.addr + i * 8 + 8, ti=td, raw=raw, name=_msvc_demangle(raw), offset=off))
        else:
            names = ["_ZTVN10__cxxabiv117__class_type_infoE", "_ZTVN10__cxxabiv120__si_class_type_infoE",
                     "_ZTVN10__cxxabiv121__vmi_class_type_infoE"]
            roots = []
            for n in names:
                if n in self.exports:
                    roots.append(self.exports[n] + 0x10)
                elif n in self.ext_sym_index:
                    roots.append(EXT_BASE + self.ext_sym_index[n] * 0x1000 + 0x10)
            tis = set()
            for r in roots:
                tis.update(self.find_ptrs(r))
            if not tis:
                self._vt = []
                return self._vt
            tarr = np.array(sorted(tis), dtype=np.uint64)
            for s in self.segs:
                if s.x:
                    continue
                arr = np.frombuffer(s.data, dtype="<u8", count=len(s.data) // 8)
                hit = np.nonzero(np.isin(arr, tarr))[0]
                for i in hit.tolist():
                    if i == 0:
                        continue
                    off = struct.unpack("<q", struct.pack("<Q", int(arr[i - 1])))[0]
                    if off > 0:
                        continue
                    ti = int(arr[i])
                    np_ = self.u64(ti + 8)
                    raw = self.read(np_, 512).split(b"\0")[0].decode(errors="replace") if np_ is not None and self.seg_of(np_) else ""
                    if raw.startswith("*"):
                        raw = raw[1:]
                    vt.append(dict(addr=s.addr + i * 8 + 8, ti=ti, raw=raw, name=_itanium_demangle(raw), offset=-off))
        self._vt = vt
        return vt

    def find_vtable(self, name):
        for v in self.vtables():
            if v["offset"] != 0:
                continue
            if self.kind == "pe":
                if v["raw"] == ".?AV%s@@" % name or v["name"] == name:
                    return v["addr"]
                if v["name"].startswith("class ") and v["name"][6:] == name:
                    return v["addr"]
                if v["name"].startswith("struct ") and v["name"][7:] == name:
                    return v["addr"]
            else:
                if v["raw"] == "%d%s" % (len(name), name) or v["name"] == name:
                    return v["addr"]
        return 0

    def typeinfo_from_name(self, name):
        for v in self.vtables():
            dn = v["name"]
            if dn == name:
                return v["ti"]
            if self.kind == "pe":
                if dn.startswith("class ") and dn[6:] == name:
                    return v["ti"]
                if dn.startswith("struct ") and dn[7:] == name:
                    return v["ti"]
        return 0

    def vfuncs(self, name):
        v = self.find_vtable(name)
        out = []
        if not v:
            return out
        while True:
            p = self.u64(v)
            if p is None or not self.is_exec(p):
                return out
            out.append(p)
            v += 8


def _msvc_demangle(raw):
    m = re.fullmatch(r"\.\?A([VU])([A-Za-z_0-9]+)@@", raw)
    if m:
        return ("class " if m.group(1) == "V" else "struct ") + m.group(2)
    return raw


def _itanium_demangle(raw):
    def ident(s, i):
        m = re.match(r"(\d+)", s[i:])
        if not m:
            return None, i
        n = int(m.group(1))
        j = i + len(m.group(1))
        return s[j:j + n], j + n
    if raw.startswith("N") and raw.endswith("E"):
        parts, i = [], 1
        while i < len(raw) - 1:
            p, i2 = ident(raw, i)
            if p is None:
                return raw
            parts.append(p)
            i = i2
        return "::".join(parts)
    p, i = ident(raw, 0)
    if p is not None and i == len(raw):
        return p
    return raw


# ---------------------------------------------------------------- workers
_W = {}


def _winit(path):
    _W["m"] = load(path)
    _W["md"] = new_md()


def _code_at(m, a, n):
    return m.read(a, n) or b""


def _decode_linear(m, md, start, end, cb):
    """Linear decode [start,end) like ModSharp (skip 1 byte on failure). cb(ins) -> False to stop."""
    ip = start
    seg = m.seg_of(start)
    if seg is None:
        return
    data = seg.data
    base = seg.addr
    lim = min(end, seg.addr + seg.size)
    while ip < lim:
        progressed = False
        for ins in md.disasm(data[ip - base:lim - base], ip):
            progressed = True
            if cb(ins) is False:
                return
            ip = ins.address + ins.size
        if ip < lim:
            cb(None)
            ip += 1


def _rip_targets(ins):
    out = []
    for op in ins.operands:
        if op.type == X.X86_OP_MEM and op.mem.base == X.X86_REG_RIP:
            out.append(ins.address + ins.size + op.mem.disp)
    return out


def _is_relbranch(ins):
    return (G_BRREL in ins.groups) or (ins.id == X.X86_INS_CALL and ins.opcode[0] == 0xE8)


def _pe_decode(ranges):
    m, md = _W["m"], _W["md"]
    xsegs = [(s.addr, s.addr + s.size) for s in m.segs if s.x]
    dsegs = [(s.addr, s.addr + s.size) for s in m.segs if not s.x]

    def in_t(a):
        return any(lo <= a < hi for lo, hi in xsegs)

    def in_d(a):
        return any(lo <= a < hi for lo, hi in dsegs)
    auth_s, auth_e = None, None
    refs, jrefs, cands = [], [], []
    # authoritative check for candidates: done by caller
    for (fs, fe) in ranges:
        st = {"jt": 0}

        def cb(ins, fs=fs, fe=fe, st=st):
            if ins is None:
                return True
            if st["jt"] and ins.address >= st["jt"]:
                return False
            ip = ins.address
            op0 = ins.opcode[0]
            if ins.id == X.X86_INS_CALL and op0 == 0xE8 and ins.operands and ins.operands[0].type == X.X86_OP_IMM:
                t = ins.operands[0].imm
                if in_t(t):
                    refs.append((t, ip, fs))
                    cands.append(t)
            elif ins.id == X.X86_INS_JMP and op0 == 0xE9 and ins.operands and ins.operands[0].type == X.X86_OP_IMM:
                t = ins.operands[0].imm
                if in_t(t):
                    jrefs.append((t, ip, fs))
                    if t < fs or t >= fe:
                        cands.append(t)
            for t in _rip_targets(ins):
                if in_d(t):
                    refs.append((t, ip, fs))
            if (not st["jt"]) and ins.id in (X.X86_INS_MOV, X.X86_INS_MOVSXD) and len(ins.operands) > 1:
                src = ins.operands[1]
                if src.type == X.X86_OP_MEM and src.mem.index != 0 and src.mem.segment == 0 and src.mem.scale != 0 and src.mem.disp > 0 and src.mem.base != X.X86_REG_RIP:
                    t = src.mem.disp + m.base
                    if in_t(t):
                        st["jt"] = t
            return True
        _decode_linear(m, md, fs, fe, cb)
    return (np.array(refs, dtype=np.int64).reshape(-1, 3), np.array(jrefs, dtype=np.int64).reshape(-1, 3), cands)


def _elf_decode(chunk):
    m, md = _W["m"], _W["md"]
    seg_start, seg_end, dstart, cstart, cend = chunk
    xsegs = [(s.addr, s.addr + s.size) for s in m.segs if s.x]
    dsegs = [(s.addr, s.addr + s.size) for s in m.segs if not s.x]
    dmin = min(a for a, _ in dsegs)
    dmax = max(b for _, b in dsegs)

    def in_t(a):
        return any(lo <= a < hi for lo, hi in xsegs)

    def in_d(a):
        return dmin <= a < dmax and any(lo <= a < hi for lo, hi in dsegs)
    funcs, refs, jrefs = [], [], []
    st = {"pc": None, "pm": None, "hp": False}
    seg = m.seg_of(cstart)
    data, base = seg.data, seg.addr
    ip = dstart
    lim = min(cend + 16, seg_end)
    while ip < cend:
        stopped = False
        for ins in md.disasm(data[ip - base:lim - base], ip):
            if ins.address >= cend:
                stopped = True
                break
            a = ins.address
            if a >= cstart:
                rel = _is_relbranch(ins) or bool(_rip_targets(ins))
                if rel:
                    op0 = ins.opcode[0]
                    if op0 == 0xE8 and ins.id == X.X86_INS_CALL:
                        t = ins.operands[0].imm
                        if in_t(t):
                            funcs.append(t)
                            refs.append((t, a))
                    elif op0 == 0xE9 and ins.id == X.X86_INS_JMP:
                        t = ins.operands[0].imm
                        if in_t(t):
                            jrefs.append((t, a))
                            if st["pc"] != "call" and (t & 15) == 0 and st["hp"] and (st["pc"] == "pop" or st["pm"] == "leave"):
                                funcs.append(t)
                    for t in _rip_targets(ins):
                        if in_d(t):
                            refs.append((t, a))
                        elif in_t(t):
                            funcs.append(t)
            g = ins.groups
            st["pc"] = "call" if G_CALL in g else ("pop" if ins.mnemonic.startswith("pop") else "x")
            st["pm"] = ins.mnemonic
            st["hp"] = True
            ip = a + ins.size
        if stopped:
            break
        if ip < cend:
            st["hp"] = False
            ip += 1
    return (np.array(funcs, dtype=np.int64), np.array(refs, dtype=np.int64).reshape(-1, 2), np.array(jrefs, dtype=np.int64).reshape(-1, 2))


def _is_zero_pad(m, a, lim):
    if a >= lim:
        return False
    n = min(8, lim - a)
    b = m.read(a, n)
    return b == b"\0" * n


def _recover_end(m, md, start, hard_end, auth_starts, accepted):
    if start >= hard_end:
        return 0
    b0 = m.read(start, 1)
    if not b0 or b0[0] == 0xCC or _is_zero_pad(m, start, hard_end):
        return 0
    ip = start
    required = start
    last_call = False
    acc_sorted = sorted(accepted)
    while ip < hard_end:
        if _is_zero_pad(m, ip, hard_end):
            if ip < required:
                ip += 1
                last_call = False
                continue
            return ip if last_call else 0
        code = m.read(ip, min(15, hard_end - ip))
        ins = next(md.disasm(code, ip), None)
        if ins is None:
            return 0
        if ip == start and ins.id == X.X86_INS_NOP:
            return 0
        nxt = ip + ins.size
        in_call = False
        if ins.opcode[0] == 0xE8 and ins.id == X.X86_INS_CALL:
            in_call = m.is_exec(ins.operands[0].imm)
        g = ins.groups
        if G_BRREL in g and G_JUMP in g and ins.operands and ins.operands[0].type == X.X86_OP_IMM:
            t = ins.operands[0].imm
            inr = start <= t < hard_end
            cond = ins.id != X.X86_INS_JMP
            if cond:
                if inr:
                    required = max(required, t + 1)
                else:
                    ia = bisect.bisect_left(auth_starts, t)
                    ib = bisect.bisect_left(acc_sorted, t)
                    if not ((ia < len(auth_starts) and auth_starts[ia] == t) or (ib < len(acc_sorted) and acc_sorted[ib] == t)):
                        return 0
                last_call = False
                ip = nxt
                continue
            if inr:
                if t > ip:
                    required = max(required, t + 1)
                    last_call = False
                    ip = t
                    continue
                if nxt >= required:
                    return nxt
                last_call = False
                ip = nxt
                continue
            if ins.opcode[0] != 0xE9 or not m.is_exec(t):
                return 0
            if nxt >= required:
                return nxt
            last_call = False
            ip = nxt
            continue
        if G_RET in g or ins.id == X.X86_INS_JMP or ins.id in (X.X86_INS_INT3, X.X86_INS_UD2):
            if nxt >= required:
                return nxt
        last_call = in_call
        ip = nxt
    return ip if last_call else 0


def _cfg_end(m, start, hard_end):
    md = _W.get("md") or new_md()
    _W["md"] = md
    blocks = []
    visited = {start}
    work = [start]
    while work:
        bs = work.pop()
        ip = bs
        term = False
        while ip < hard_end:
            code = m.read(ip, min(15, hard_end - ip))
            ins = next(md.disasm(code, ip), None) if code else None
            if ins is None:
                break
            nxt = ip + ins.size
            g = ins.groups
            if G_RET in g or ins.id in (X.X86_INS_INT3, X.X86_INS_UD2):
                blocks.append((bs, nxt))
                term = True
                break
            if G_JUMP in g:
                blocks.append((bs, nxt))
                if G_BRREL in g and ins.operands and ins.operands[0].type == X.X86_OP_IMM:
                    t = ins.operands[0].imm
                    if start <= t < hard_end and t not in visited:
                        visited.add(t)
                        work.append(t)
                    if ins.id != X.X86_INS_JMP and nxt < hard_end and nxt not in visited:
                        visited.add(nxt)
                        work.append(nxt)
                term = True
                break
            ip = nxt
        if not term and ip > bs:
            blocks.append((bs, ip))
    end = start
    for a, b in blocks:
        end = max(end, b)
    if not blocks:
        code = m.read(start, min(15, hard_end - start))
        ins = next(md.disasm(code, start), None) if code else None
        end = start + (ins.size if ins else 1)
    return end


def _find_last_real(m, limit, floor, xs, xe):
    md = _W.get("md") or new_md()
    eor = floor
    cur = floor
    chain = False
    while cur < limit:
        b = m.read(cur, 1)[0]
        if b == 0:
            cur += 1
            chain = False
            continue
        if b == 0xCC:
            cur += 1
            if chain:
                eor = cur
            chain = False
            continue
        code = m.read(cur, min(15, limit - cur))
        ins = next(md.disasm(code, cur), None)
        if ins is None:
            cur += 1
            chain = False
            continue
        iip = cur
        cur += ins.size
        if ins.id == X.X86_INS_NOP:
            chain = False
            continue
        chain = True
        g = ins.groups
        if G_RET in g or ins.id == X.X86_INS_JMP or ins.id == X.X86_INS_UD2:
            eor = cur
            chain = False
            continue
        if ins.opcode[0] == 0xE8 and ins.id == X.X86_INS_CALL:
            t = ins.operands[0].imm
            if xs <= t < xe:
                eor = cur
    return eor
