"""Bound code analysis of PS4 executable segments that also hold read-only data."""

from pathlib import Path
import json
import platform
import signal
import struct
import subprocess
import sys
import tempfile

import test_ps4_executable as fixture

PT_GNU_EH_FRAME = 0x6474E550
DT_FINI = 13
FINI = 0x60
PLT = 0x70
STUB = PLT + 16
RODATA = 0x90
EH_FRAME_HEADER = 0x200
EH_FRAME = 0x220
UNDECODABLE = bytes.fromhex("0f78c0" "0f05" "cc")
FINI_CODE = bytes.fromhex("554889e5" "5d" "c3")
SWITCH = 0x30
TABLE = 0x50
SWITCH_END = 0x58
SWITCH_CODE = (b"\x48\x8d\x05" + struct.pack("<i", TABLE - (SWITCH + 7)) + bytes.fromhex("48630cb8" "4801c1" "85ff" "7402" "ffe1")
               + b"\xe8" + struct.pack("<i", STUB - (SWITCH + 0x19)) + b"\x90" * 7 + bytes.fromhex("64f80000"))
FINI_WITH_SYSCALL = bytes.fromhex("554889e5" "0f05" "5d" "c3")


def plt():
    got = fixture.RELRO_ADDRESS
    resolver = (b"\xff\x35" + struct.pack("<i", got + 8 - (PLT + 6))
                + b"\xff\x25" + struct.pack("<i", got + 16 - (PLT + 12)) + bytes.fromhex("0f1f4000"))
    stub = (b"\xff\x25" + struct.pack("<i", fixture.GOT_SLOT - (STUB + 6))
            + b"\x68" + struct.pack("<I", 0) + b"\xe9" + struct.pack("<i", PLT - (STUB + 16)))
    return resolver + stub


def eh_frame(functions):
    cie = struct.pack("<I", 0) + bytes([1]) + b"zR\0" + bytes([1, 0x78, 16, 1, 0x1B]) + bytes([0x0C, 7, 8, 0x90, 1])
    cie += bytes(-(len(cie) + 4) % 8)
    frame = bytearray(struct.pack("<I", len(cie)) + cie)
    entries = []
    for begin, end in functions:
        position = EH_FRAME + len(frame)
        body = struct.pack("<I", len(frame) + 4) + struct.pack("<i", begin - (position + 8)) + struct.pack("<I", end - begin) + bytes([0])
        body += bytes(-(len(body) + 4) % 8)
        entries.append((begin, position))
        frame += struct.pack("<I", len(body)) + body
    frame += struct.pack("<I", 0)
    header = bytearray(bytes([1, 0x1B, 0x03, 0x3B]) + struct.pack("<i", EH_FRAME - (EH_FRAME_HEADER + 4)) + struct.pack("<I", len(entries)))
    for begin, position in sorted(entries):
        header += struct.pack("<ii", begin - EH_FRAME_HEADER, position - EH_FRAME_HEADER)
    return bytes(header), bytes(frame)


def executable(fini=FINI_CODE, with_plt=True, rodata_pointer=False):
    relocations = [(fixture.RELRO_ADDRESS + 0x20, 8, fixture.ENTRY)]
    if rodata_pointer:
        relocations.append((fixture.RELRO_ADDRESS + 0x28, 8, RODATA))
    data = fixture.eboot(relocations=relocations)
    headers = fixture.program_headers(data)
    dynamic = next(header for header in headers if header[0] == fixture.PT_DYNAMIC)
    position = dynamic[2]
    while struct.unpack_from("<q", data, position)[0] != 0:
        position += 16
    struct.pack_into("<qQqQ", data, position, DT_FINI, FINI, 0, 0)
    for index, header in enumerate(headers):
        if header[0] == fixture.PT_DYNAMIC:
            struct.pack_into("<QQ", data, 64 + index * 56 + 32, header[5] + 16, header[6] + 16)
    text = fixture.TEXT_OFFSET
    data[text + FINI:text + FINI + len(fini)] = fini
    if with_plt:
        data[text + PLT:text + PLT + 32] = plt()
        struct.pack_into("<Q", data, fixture.RELRO_OFFSET + fixture.GOT_SLOT - fixture.RELRO_ADDRESS, STUB + 6)
    data[text + RODATA:text + RODATA + len(UNDECODABLE)] = UNDECODABLE
    data[text + SWITCH:text + SWITCH + len(SWITCH_CODE)] = SWITCH_CODE
    header, frame = eh_frame([(fixture.ENTRY, fixture.ENTRY + len(fixture.CHECK_IMPORT)), (SWITCH, SWITCH_END)])
    data[text + EH_FRAME_HEADER:text + EH_FRAME_HEADER + len(header)] = header
    data[text + EH_FRAME:text + EH_FRAME + len(frame)] = frame
    struct.pack_into("<IIQQQQQQ", data, 64 + len(headers) * 56, PT_GNU_EH_FRAME, 4, text + EH_FRAME_HEADER,
                     EH_FRAME_HEADER, EH_FRAME_HEADER, len(header), len(header), 4)
    struct.pack_into("<H", data, 56, len(headers) + 1)
    return data


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="orbridge-ps4-code-extent-") as directory:
        work = Path(directory)

        def convert(name, data, options=()):
            case = work / name
            (case / "sce_module").mkdir(parents=True)
            (case / "sce_module" / "libProvider.prx").write_bytes(fixture.provider_module())
            source = case / "eboot.bin"
            source.write_bytes(data)
            output = case / ("eboot.exe" if "--windows" in options else "eboot.elf")
            result = subprocess.run([str(relinker), *options, str(source), str(output)],
                                    capture_output=True, text=True, timeout=30)
            return result, output

        result, output = convert("linux", executable(), ("--registry",))
        assert result.returncode == 0, (result.stdout, result.stderr)
        entries = json.loads((output.parent / "eboot.registry.json").read_text())
        sites = sorted(int(site, 16) for entry in entries for site in entry["callSites"])
        assert sites == [fixture.ENTRY, STUB], (sites, entries)
        if sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64"):
            output.chmod(0o755)
            executed = subprocess.run([str(output)], capture_output=True, timeout=20)
            assert executed.returncode == -signal.SIGTRAP, (executed.returncode, executed.stderr)

        result, output = convert("intel", executable(), ("--to-intel",))
        assert result.returncode == 0, (result.stdout, result.stderr)

        result, output = convert("windows", executable(rodata_pointer=True), ("--windows",))
        assert result.returncode == 0 and output.read_bytes().startswith(b"MZ"), (result.stdout, result.stderr)

        result, output = convert("no-plt", executable(with_plt=False))
        assert result.returncode == 0, (result.stdout, result.stderr)

        result, output = convert("fini-syscall", executable(FINI_WITH_SYSCALL))
        assert result.returncode == 2 and f"Forbidden syscall instruction at code offset 0x{FINI + 4:x}" in result.stderr, (
            result.stdout, result.stderr)

        broken = executable()
        struct.pack_into("<Q", broken, fixture.RELRO_OFFSET + fixture.GOT_SLOT - fixture.RELRO_ADDRESS, RODATA)
        result, output = convert("bad-plt-slot", broken)
        assert result.returncode == 2 and "PLT slot does not hold the address of a lazy-binding stub" in result.stderr, (
            result.stdout, result.stderr)
    print("PS4 code extent tests passed")


if __name__ == "__main__":
    main()
