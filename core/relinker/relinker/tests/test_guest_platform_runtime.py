"""Run relinked PS4 and PS5 executables against the host libkernel.prx and libc.prx on Linux."""

from pathlib import Path
import base64
import hashlib
import platform
import signal
import struct
import subprocess
import sys
import tempfile

import test_ps4_executable as fixture

SKIPPED = 77
NID_SUFFIX = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")
PS5_NEEDED_MODULE = 0x61000045
PS5_IMPORT_LIB = 0x61000049
PLATFORM_QUERY = "ApplicationGuestPlatform_nid_no_patch"


def nid(name):
    digest = hashlib.sha1(name.encode() + NID_SUFFIX).digest()[:8][::-1]
    return base64.b64encode(digest).decode()[:11].replace("/", "-")


def executable(ps4, expected_platform):
    strings = fixture.Strings()
    kernel_file, libc_file = strings.add("libkernel.prx"), strings.add("libc.prx")
    kernel, libc = strings.add("libkernel"), strings.add("libc")
    needed_module = fixture.DT_SCE_NEEDED_MODULE if ps4 else PS5_NEEDED_MODULE
    import_library = fixture.DT_SCE_IMPORT_LIB if ps4 else PS5_IMPORT_LIB
    tags = [(fixture.DT_NEEDED, kernel_file), (fixture.DT_NEEDED, libc_file),
            (needed_module, fixture.module_value(1, kernel)), (needed_module, fixture.module_value(2, libc)),
            (import_library, fixture.library_value(0, kernel)), (import_library, fixture.library_value(1, libc))]
    slots = (fixture.GOT_SLOT, fixture.GOT_SLOT + 8)
    code = bytearray(b"\x48\x83\xec\x08")

    def call(slot):
        code.extend(b"\xff\x15" + struct.pack("<i", slot - (fixture.ENTRY + len(code) + 6)))

    def fail_unless_equal(compare):
        code.extend(compare + b"\x75\x00")
        return len(code) - 1

    call(slots[0])
    code.extend(b"\x48\x8d\x0d" + struct.pack("<i", fixture.DATA_ADDRESS - (fixture.ENTRY + len(code) + 7)))
    jumps = [fail_unless_equal(b"\x48\x39\xc8")]
    call(slots[1])
    jumps.append(fail_unless_equal(b"\x83\xf8" + bytes([expected_platform])))
    code.extend(b"\xcc")
    for jump in jumps:
        code[jump] = len(code) - jump - 1
    code.extend(b"\x0f\x0b")
    symbols = [(nid("sceKernelGetProcParam") + "#A#B", 0x12, 0, 0, 0), (PLATFORM_QUERY + "#B#C", 0x12, 0, 0, 0)]
    return fixture.image(0xFE10, bytes(code), tags, symbols, strings, plt=[(slot, ((index + 1) << 32) | 7, 0) for index, slot in enumerate(slots)],
                         procparam=True, interpreter=ps4, standard_tables=not ps4)


def main():
    relinker = Path(sys.argv[1]).resolve()
    libraries = Path(sys.argv[2]).resolve()
    if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64", "AMD64"):
        print("Guest platform runtime test requires Linux x86-64")
        return SKIPPED
    with tempfile.TemporaryDirectory(prefix="orbridge-guest-platform-runtime-") as directory:
        work = Path(directory)
        for name, ps4, value, diagnostic in (("ps4", True, 4, "Detected guest platform: PS4"),
                                             ("ps5", False, 5, "Detected guest platform: PS5"),
                                             ("ps4-checks-5", True, 5, "Detected guest platform: PS4")):
            source = work / (name + ".bin")
            output = work / (name + ".elf")
            source.write_bytes(executable(ps4, value))
            result = subprocess.run([str(relinker), "--skip-sce-module", "--rpath", str(libraries), str(source), str(output)],
                                    capture_output=True, text=True, timeout=30)
            assert result.returncode == 0 and diagnostic in result.stdout, (name, result.stdout, result.stderr)
            output.chmod(0o755)
            executed = subprocess.run([str(output)], capture_output=True, timeout=30)
            expected = -signal.SIGILL if name == "ps4-checks-5" else -signal.SIGTRAP
            assert executed.returncode == expected, (name, executed.returncode, executed.stdout, executed.stderr)
    print("Guest platform runtime tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
