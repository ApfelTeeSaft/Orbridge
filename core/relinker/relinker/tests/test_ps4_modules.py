"""Relink PS4 module conventions: initializer at address 0, section-symbol TLS module relocations and per-module import binding."""

from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import tempfile

import test_ps4_executable as fixture

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
DT_INIT = 12
DT_PREINIT_ARRAY = 32
DT_PREINIT_ARRAYSZ = 33
PT_TLS = 7
R_X86_64_64 = 1
R_X86_64_DTPMOD64 = 16
TAGS = {
    True: {"info": 0x6100000D, "needed": 0x6100000F, "export": 0x61000013, "import": 0x61000015},
    False: {"info": 0x61000043, "needed": 0x61000045, "export": 0x61000047, "import": 0x61000049},
}
COUNTER = fixture.DATA_ADDRESS + 0x100
TLS_MODULE_SLOT = fixture.DATA_ADDRESS + 0x300
STORE_42_AT_ZERO = (b"\xc7\x05" + struct.pack("<i", COUNTER - 10) + struct.pack("<I", 42) + b"\xc3"
                    + b"\x90" * (fixture.ENTRY - 11))
LOAD_COUNTER = b"\x8b\x05" + struct.pack("<i", COUNTER - (fixture.ENTRY + 6)) + b"\xc3"


def append_header(data, header):
    count, = struct.unpack_from("<H", data, 56)
    struct.pack_into("<IIQQQQQQ", data, 64 + count * 56, header[0], header[1], header[2], header[3], header[3],
                     header[4], header[5], header[6])
    struct.pack_into("<H", data, 56, count + 1)


def module(ps4, name, exported, imported=(), code=fixture.PROVIDE_42, extra_tags=(), extra_symbols=(), extra_relocations=()):
    tags_for = TAGS[ps4]
    strings = fixture.Strings()
    own = strings.add(name)
    tags = [(tags_for["info"], fixture.module_value(0, own)), (tags_for["export"], fixture.library_value(0, own)), *extra_tags]
    symbols = [*extra_symbols, (exported + "#A#A", 0x12, 1, fixture.ENTRY, len(code))]
    relocations = [(fixture.RELRO_ADDRESS, 8, fixture.ENTRY), *extra_relocations]
    for index, (symbol, provider) in enumerate(imported, start=1):
        tags += [(fixture.DT_NEEDED, strings.add(provider + ".prx")),
                 (tags_for["needed"], fixture.module_value(index, strings.add(provider))),
                 (tags_for["import"], fixture.library_value(index, strings.add(provider)))]
        symbols.append((symbol + "#" + ALPHABET[index] + "#" + ALPHABET[index], 0x12, 0, 0, 0))
        relocations.append((fixture.DATA_ADDRESS + 8 * index, (len(symbols) << 32) | R_X86_64_64, 0))
    return fixture.image(0xFE18, code, tags, symbols, strings, relocations=relocations, standard_tables=not ps4)


def executable(ps4, imported=(("Xprovide000", "libProvider"),)):
    tags_for = TAGS[ps4]
    strings = fixture.Strings()
    tags = [(tags_for["info"], fixture.module_value(0, strings.add("eboot")))] if ps4 else []
    symbols = []
    relocations = []
    for index, (symbol, provider) in enumerate(imported, start=1):
        tags += [(fixture.DT_NEEDED, strings.add(provider + ".prx")),
                 (tags_for["needed"], fixture.module_value(index, strings.add(provider))),
                 (tags_for["import"], fixture.library_value(index - 1, strings.add(provider)))]
        symbols.append((symbol + "#" + ALPHABET[index - 1] + "#" + ALPHABET[index], 0x12, 0, 0, 0))
        relocations.append((fixture.GOT_SLOT + 8 * (index - 1), (index << 32) | (7 if index == 1 else R_X86_64_64), 0))
    return fixture.image(0xFE10, fixture.CHECK_IMPORT, tags, symbols, strings, plt=relocations[:1], relocations=relocations[1:],
                         procparam=True, interpreter=ps4, standard_tables=not ps4)


def dynamic(data, count=None):
    tags, string, symbols, offset = fixture.dynamic_entries(data)
    if count is None:
        count, = struct.unpack_from("<I", data, offset(next(value for tag, value in tags if tag == 4)) + 4)
    names = [string(struct.unpack_from("<I", data, symbols + index * 24)[0]) for index in range(count)]
    needed = [string(value) for tag, value in tags if tag == fixture.DT_NEEDED]
    relocations = []
    for address_tag, size_tag in ((7, 8), (23, 2)):
        address = next((value for tag, value in tags if tag == address_tag), None)
        if address is None:
            continue
        size = next(value for tag, value in tags if tag == size_tag)
        start = offset(address)
        relocations += [struct.unpack_from("<QQq", data, start + position) for position in range(0, size, 24)]
    return names, needed, relocations


def main():
    relinker = Path(sys.argv[1]).resolve()
    native = sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64")
    with tempfile.TemporaryDirectory(prefix="orbridge-ps4-modules-") as directory:
        work = Path(directory)

        def convert(name, eboot, modules, options=()):
            case = work / name
            (case / "sce_module").mkdir(parents=True)
            for filename, data in modules.items():
                (case / "sce_module" / filename).write_bytes(data)
            source = case / "eboot.bin"
            source.write_bytes(eboot)
            output = case / ("eboot.exe" if "--windows" in options else "eboot.elf")
            result = subprocess.run([str(relinker), *options, str(source), str(output)],
                                    capture_output=True, text=True, timeout=30)
            return result, output

        def guest(output, filename):
            return (output.parent / "app0" / "sce_module" / (filename + ".guest.prx")).read_bytes()

        initializer = [(DT_INIT, 0), (DT_PREINIT_ARRAY, fixture.DATA_ADDRESS + 0x200), (DT_PREINIT_ARRAYSZ, 8)]

        def initialized(ps4):
            data = module(ps4, "libProvider", fixture.IMPORT, code=LOAD_COUNTER, extra_tags=initializer)
            data[fixture.TEXT_OFFSET:fixture.TEXT_OFFSET + len(STORE_42_AT_ZERO)] = STORE_42_AT_ZERO
            return data

        result, output = convert("initializer", fixture.eboot(), {"libProvider.prx": initialized(True)})
        assert result.returncode == 0, (result.stdout, result.stderr)
        if native:
            output.chmod(0o755)
            executed = subprocess.run([str(output)], capture_output=True, timeout=20)
            assert executed.returncode == -signal.SIGTRAP, (executed.returncode, executed.stderr)
        result, output = convert("initializer-windows", fixture.eboot(), {"libProvider.prx": initialized(True)}, ("--windows",))
        assert result.returncode == 0, (result.stdout, result.stderr)
        result, output = convert("initializer-ps5", executable(False), {"libProvider.prx": initialized(False)})
        assert result.returncode == 2 and "Guest PREINIT_ARRAY has no module initializer" in result.stderr, (result.stdout, result.stderr)

        section = [("", 3, 0, 0, 0)]

        def tls_module(relocation_type):
            data = module(True, "libProvider", fixture.IMPORT, extra_symbols=section,
                          extra_relocations=[(TLS_MODULE_SLOT, (1 << 32) | relocation_type, 0)])
            append_header(data, (PT_TLS, 4, fixture.DATA_OFFSET + 0x400, fixture.DATA_ADDRESS + 0x400, 0x10, 0x10, 8))
            return data

        result, output = convert("tls-module", fixture.eboot(), {"libProvider.prx": tls_module(R_X86_64_DTPMOD64)})
        assert result.returncode == 0, (result.stdout, result.stderr)
        _, _, relocations = dynamic(guest(output, "libProvider.prx"))
        assert [info for address, info, _ in relocations if address == TLS_MODULE_SLOT] == [R_X86_64_DTPMOD64], relocations
        result, output = convert("tls-module-windows", fixture.eboot(), {"libProvider.prx": tls_module(R_X86_64_DTPMOD64)}, ("--windows",))
        assert result.returncode == 0, (result.stdout, result.stderr)
        result, output = convert("section-pointer", fixture.eboot(), {"libProvider.prx": tls_module(R_X86_64_64)})
        assert result.returncode == 2 and "Invalid guest symbol relocation" in result.stderr, (result.stdout, result.stderr)

        def pair(ps4):
            return {"libAlpha.prx": module(ps4, "libAlpha", "Xshared0000", [("Yshared0000", "libBeta")]),
                    "libBeta.prx": module(ps4, "libBeta", "Yshared0000", [("Xshared0000", "libSceLibcInternal")])}

        eboot = executable(True, [("Xshared0000", "libSceLibcInternal"), ("Yshared0000", "libBeta")])
        result, output = convert("by-module", eboot, pair(True))
        assert result.returncode == 0, (result.stdout, result.stderr)
        names, needed, _ = dynamic(guest(output, "libAlpha.prx"))
        assert "Yshared0000#guest" in names and "Xshared0000#guest" in names, names
        assert "$ORIGIN/libBeta.prx.guest.prx" in needed, needed
        names, needed, _ = dynamic(guest(output, "libBeta.prx"))
        assert "Xshared0000" in names and "Yshared0000#guest" in names, names
        assert not any("libAlpha" in name for name in needed), needed
        names, _, _ = dynamic(output.read_bytes(), 3)
        assert names[1:] == ["Xshared0000", "Yshared0000#guest"], names
        result, output = convert("by-module-windows", eboot, pair(True), ("--windows",))
        assert result.returncode == 0, (result.stdout, result.stderr)

        result, output = convert("flat-ps5", executable(False), pair(False))
        assert result.returncode == 2 and "Cyclic guest initialization dependency" in result.stderr, (result.stdout, result.stderr)
    print("PS4 module tests passed")


if __name__ == "__main__":
    main()
