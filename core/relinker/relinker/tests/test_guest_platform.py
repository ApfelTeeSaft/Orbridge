"""Check guest platform detection from SCE module and library tags and the --platform option."""

from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from test_guest_module_directories import module_with_symbol

PS4_NEEDED_MODULE = 0x6100000F
PS4_IMPORT_LIB = 0x61000015
PS5_NEEDED_MODULE = 0x61000045
PS5_IMPORT_LIB = 0x61000049
STRINGS = b"\0libkernel.prx\0libkernel\0"
MODULE_NAME = STRINGS.index(b"libkernel\0")


def executable(metadata=()):
    image = bytearray(0x2000)
    image[:16] = b"\x7fELF\x02\x01\x01\x09" + bytes(8)
    struct.pack_into("<HHIQQQIHHHHHH", image, 16,
                     0xFE10, 62, 1, 0x10, 64, 0, 0, 64, 56, 5, 64, 0, 0)
    tags = [(5, 0x400), (10, len(STRINGS)), (6, 0x500), (11, 24),
            (7, 0x600), (8, 0), (9, 24), (1, 1)]
    tags += [(tag, (1 << 48) | MODULE_NAME) for tag in metadata]
    tags.append((0, 0))
    struct.pack_into("<IIQQQQQQ", image, 64, 1, 5, 0x1000, 0, 0, 0x1000, 0x1000, 0x1000)
    struct.pack_into("<IIQQQQQQ", image, 120,
                     2, 6, 0x1800, 0x800, 0x800, len(tags) * 16, len(tags) * 16, 8)
    for index in range(2, 5):
        struct.pack_into("<IIQQQQQQ", image, 64 + index * 56, 0x6FFFFF01, 0, 0, 0, 0, 0, 0, 1)
    image[0x1010:0x1016] = b"\xb8\x2a\x00\x00\x00\xc3"
    image[0x1400:0x1400 + len(STRINGS)] = STRINGS
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", image, 0x1800 + index * 16, *tag)
    return image


def module(tag):
    image = module_with_symbol(True)
    struct.pack_into("<qQ", image, 0x680, tag, 1 << 48)
    struct.pack_into("<qQ", image, 0x690, 0, 0)
    struct.pack_into("<QQ", image, 176 + 32, 160, 160)
    return image


def mixed_module():
    image = module(PS5_NEEDED_MODULE)
    struct.pack_into("<qQ", image, 0x690, PS4_NEEDED_MODULE, 1 << 48)
    struct.pack_into("<qQ", image, 0x6a0, 0, 0)
    struct.pack_into("<QQ", image, 176 + 32, 176, 176)
    return image


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="orbridge-guest-platform-") as directory:
        work = Path(directory)

        def convert(name, image, options=(), modules=None):
            case = work / name
            case.mkdir()
            source = case / "input.elf"
            source.write_bytes(image)
            if modules is None:
                options = ("--skip-sce-module", *options)
            else:
                (case / "prx").mkdir()
                for filename, data in modules.items():
                    (case / "prx" / filename).write_bytes(data)
            output = case / "output.elf"
            result = subprocess.run([str(relinker), *options, str(source), str(output)],
                                    capture_output=True, text=True, timeout=30)
            return result, output

        def succeeds(name, image, diagnostic, options=(), modules=None):
            result, output = convert(name, image, options, modules)
            assert result.returncode == 0 and output.exists(), (name, result.stdout, result.stderr)
            assert diagnostic in result.stdout, (name, result.stdout)

        def fails(name, image, code, message, options=(), modules=None):
            result, output = convert(name, image, options, modules)
            assert result.returncode == code and message in result.stderr and not output.exists(), (
                name, result.returncode, result.stdout, result.stderr)
            return result

        succeeds("ps5", executable([PS5_NEEDED_MODULE, PS5_IMPORT_LIB]),
                 "Detected guest platform: PS5 (DT_SCE_NEEDED_MODULE 0x61000045)")
        succeeds("ps5-windows", executable([PS5_NEEDED_MODULE]),
                 "Detected guest platform: PS5", ("--windows",))
        succeeds("ps5-selected", executable([PS5_NEEDED_MODULE]),
                 "Detected guest platform: PS5", ("--platform", "ps5"))
        succeeds("ps5-auto", executable([PS5_NEEDED_MODULE]),
                 "Detected guest platform: PS5", ("--platform", "auto"))
        succeeds("no-metadata", executable(),
                 "Guest platform: PS5 (no SCE module or library tags; default)")
        succeeds("no-metadata-ps5", executable(),
                 "Guest platform: PS5 (--platform; no SCE module or library tags)", ("--platform", "ps5"))

        result = fails("ps4", executable([PS4_NEEDED_MODULE, PS4_IMPORT_LIB]), 2,
                       "PS4 executables are not supported yet")
        assert "Detected guest platform: PS4 (DT_SCE_NEEDED_MODULE 0x6100000f)" in result.stdout, result.stdout
        fails("ps4-library-only", executable([PS4_IMPORT_LIB]), 2, "PS4 executables are not supported yet")
        fails("no-metadata-ps4", executable(), 2, "PS4 executables are not supported yet", ("--platform", "ps4"))

        fails("mixed", executable([PS5_NEEDED_MODULE, PS4_NEEDED_MODULE]), 2,
              "executable: conflicting PS4 (DT_SCE_NEEDED_MODULE 0x6100000f) and PS5 (DT_SCE_NEEDED_MODULE 0x61000045) module metadata")
        fails("ps5-as-ps4", executable([PS5_NEEDED_MODULE]), 2,
              "--platform ps4 conflicts with PS5 module metadata (DT_SCE_NEEDED_MODULE 0x61000045) in executable",
              ("--platform", "ps4"))
        fails("ps4-as-ps5", executable([PS4_NEEDED_MODULE]), 2,
              "--platform ps5 conflicts with PS4 module metadata", ("--platform", "ps5"))
        fails("unknown-platform", executable(), 1, "--platform must be auto, ps4 or ps5", ("--platform", "ps3"))
        trailing = subprocess.run([str(relinker), "--skip-sce-module", str(work / "ps5" / "input.elf"),
                                   str(work / "trailing.elf"), "--platform"], capture_output=True, text=True, timeout=30)
        assert trailing.returncode == 1 and "--platform requires a value" in trailing.stderr, trailing
        fails("repeated-platform", executable(), 1, "--platform must be specified at most once",
              ("--platform", "ps5", "--platform", "ps5"))

        succeeds("ps5-module", executable([PS5_NEEDED_MODULE]), "Detected guest platform: PS5",
                 modules={"a.prx": module(PS5_NEEDED_MODULE)})
        fails("ps4-module", executable([PS5_NEEDED_MODULE]), 2,
              "a.prx carries PS4 module metadata (DT_SCE_NEEDED_MODULE 0x6100000f), but the executable is PS5",
              modules={"a.prx": module(PS4_NEEDED_MODULE)})
        fails("mixed-module", executable([PS5_NEEDED_MODULE]), 2, "conflicting PS4",
              modules={"a.prx": mixed_module()})
    print("Guest platform tests passed")


if __name__ == "__main__":
    main()
