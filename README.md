# gamedata audit tools (not part of ModSharp; working tools for gamedata PRs)

Static emulation of ModSharp's gamedata resolution (Engine/src/gamedata.cpp) on CS2 binaries:
- `msemu.py`: PE/ELF loader with relocations, function index, RIP-relative reference index, RTTI/vtables (mirrors CModule).
- `resolver.py`: FindAddress / FindFunctionFromReferences / GetVScriptFunction emulation.
- `cvars.py`: static stand-in for runtime cvar refs. The ConVar object is located via its registration call.
  Then `[ptr]` refs go to object+8, and `[handle]` refs go to the object, kept only when a `mov edx/esi,-1` is within ±64 bytes.
- `audit.py`: resolve every Addresses entry: `CS2_GAME=<game dir> python audit.py <gamedata dir> new out.json`
- `canacq_check.py`: CanAcquire refs candidates (current refs and each cvar alone).
- `engoff_emu.py`: port of ResolveServerSideClientOffsets / ResolveNetworkGameServerOffsets.

Binaries: DepotDownloader (anonymous), app 730:
- depot 2347771 (windows) / 2347773 (linux)
- filelist regexes such as `regex:game/csgo/bin/win64/server\.dll$` and `regex:game/csgo/bin/linuxsteamrt64/libserver\.so$`

`CS2_GAME` points at the downloaded `game` folder. Needs python3, numpy, capstone and pyelftools (pefile if used).
