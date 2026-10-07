"""Relink a synthetic PS4 executable and bundled PS4 module and run the result on Linux."""

from pathlib import Path
import platform
import signal
import struct
import subprocess
import sys
import tempfile

PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_SCE_DYNLIBDATA = 0x61000000
PT_SCE_PROCPARAM = 0x61000001
PT_SCE_RELRO = 0x61000010
PT_SCE_COMMENT = 0x6FFFFF00
PT_SCE_VERSION = 0x6FFFFF01

DT_NEEDED = 1
DT_DEBUG = 21
DT_TEXTREL = 22
DT_FLAGS = 30
DT_SCE_FINGERPRINT = 0x61000007
DT_SCE_ORIGINAL_FILENAME = 0x61000009
DT_SCE_MODULE_INFO = 0x6100000D
DT_SCE_NEEDED_MODULE = 0x6100000F
DT_SCE_MODULE_ATTR = 0x61000011
DT_SCE_EXPORT_LIB = 0x61000013
DT_SCE_IMPORT_LIB = 0x61000015
DT_SCE_EXPORT_LIB_ATTR = 0x61000017
DT_SCE_IMPORT_LIB_ATTR = 0x61000019
DT_SCE_HASH = 0x61000025
DT_SCE_PLTGOT = 0x61000027
DT_SCE_JMPREL = 0x61000029
DT_SCE_PLTREL = 0x6100002B
DT_SCE_PLTRELSZ = 0x6100002D
DT_SCE_RELA = 0x6100002F
DT_SCE_RELASZ = 0x61000031
DT_SCE_RELAENT = 0x61000033
DT_SCE_STRTAB = 0x61000035
DT_SCE_STRSZ = 0x61000037
DT_SCE_SYMTAB = 0x61000039
DT_SCE_SYMENT = 0x6100003B
DT_SCE_HASHSZ = 0x6100003D
DT_SCE_SYMTABSZ = 0x6100003F

TEXT_OFFSET, RELRO_OFFSET, DATA_OFFSET, DYNLIB_OFFSET = 0x4000, 0x8000, 0xC000, 0x10000
TEXT_ADDRESS, RELRO_ADDRESS, DATA_ADDRESS, DYNLIB_ADDRESS = 0x0, 0x4000, 0x8000, 0xC000
STRTAB, SYMTAB, HASH, JMPREL, RELA, DYNAMIC = 0x100, 0x200, 0x260, 0x280, 0x2A0, 0x400
ENTRY = 0x10
GOT_SLOT = RELRO_ADDRESS + 0x18
IMPORT = "Xprovide000"
INTERPRETER = b"/libexec/ld-elf.so.1\0"
CHECK_IMPORT = (b"\xff\x15" + struct.pack("<i", GOT_SLOT - (ENTRY + 6))
                + bytes.fromhex("83f82a" "7501" "cc" "0f0b"))
PROVIDE_42 = bytes.fromhex("b82a000000c3")


class Strings:
    def __init__(self):
        self.data = bytearray(b"\0")

    def add(self, text):
        offset = self.data.find(text.encode() + b"\0")
        if offset <= 0:
            offset = len(self.data)
            self.data += text.encode() + b"\0"
        return offset


def module_value(identifier, name):
    return (identifier << 48) | (1 << 40) | (1 << 32) | name


def library_value(identifier, name):
    return (identifier << 48) | (1 << 32) | name


def image(elf_type, code, tags, symbols, strings, relocations=(), plt=(), relro_flags=4, headers=None,
          procparam=False, interpreter=False, standard_tables=False):
    data = bytearray(DYNLIB_OFFSET + 0x1000)
    data[:16] = b"\x7fELF\x02\x01\x01\x09" + bytes(8)
    data[TEXT_OFFSET + ENTRY:TEXT_OFFSET + ENTRY + len(code)] = code
    symbol_bytes = bytearray(24)
    for name, info, section, value, size in symbols:
        symbol_bytes += struct.pack("<IBBHQQ", strings.add(name), info, 0, section, value, size)
    for index, entry in enumerate(plt):
        struct.pack_into("<QQq", data, DYNLIB_OFFSET + JMPREL + index * 24, *entry)
    for index, entry in enumerate(relocations):
        struct.pack_into("<QQq", data, DYNLIB_OFFSET + RELA + index * 24, *entry)
    if standard_tables:
        tags = list(tags) + [
            (5, DYNLIB_ADDRESS + STRTAB), (10, len(strings.data)),
            (6, DYNLIB_ADDRESS + SYMTAB), (11, 24), (DT_SCE_SYMTABSZ, len(symbol_bytes)),
            (4, DYNLIB_ADDRESS + HASH),
            (7, DYNLIB_ADDRESS + RELA), (8, len(relocations) * 24), (9, 24), (0, 0)]
        if plt:
            tags[-1:-1] = [(3, RELRO_ADDRESS), (23, DYNLIB_ADDRESS + JMPREL), (20, 7), (2, len(plt) * 24)]
    else:
        tags = list(tags) + [
            (DT_SCE_STRTAB, STRTAB), (DT_SCE_STRSZ, len(strings.data)),
            (DT_SCE_SYMTAB, SYMTAB), (DT_SCE_SYMENT, 24), (DT_SCE_SYMTABSZ, len(symbol_bytes)),
            (DT_SCE_HASH, HASH), (DT_SCE_HASHSZ, 20),
            (DT_SCE_RELA, RELA), (DT_SCE_RELASZ, len(relocations) * 24), (DT_SCE_RELAENT, 24),
            (DT_SCE_FINGERPRINT, 0), (DT_DEBUG, 0), (DT_TEXTREL, 0), (DT_FLAGS, 4), (0, 0)]
        if plt:
            tags[-1:-1] = [(DT_SCE_PLTGOT, RELRO_ADDRESS), (DT_SCE_JMPREL, JMPREL),
                           (DT_SCE_PLTREL, 7), (DT_SCE_PLTRELSZ, len(plt) * 24)]
    data[DYNLIB_OFFSET + STRTAB:DYNLIB_OFFSET + STRTAB + len(strings.data)] = strings.data
    data[DYNLIB_OFFSET + SYMTAB:DYNLIB_OFFSET + SYMTAB + len(symbol_bytes)] = symbol_bytes
    struct.pack_into("<IIIII", data, DYNLIB_OFFSET + HASH, 1, len(symbol_bytes) // 24, 1, 0, 0)
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", data, DYNLIB_OFFSET + DYNAMIC + index * 16, *tag)
    if headers is None:
        headers = [
            (PT_LOAD, 5, TEXT_OFFSET, TEXT_ADDRESS, 0x1000, 0x1000, 0x4000),
            (PT_LOAD, 6, RELRO_OFFSET, RELRO_ADDRESS, 0x1000, 0x1000, 0x4000) if standard_tables else
            (PT_SCE_RELRO, relro_flags, RELRO_OFFSET, RELRO_ADDRESS, 0x1000, 0x1000, 0x4000),
            (PT_LOAD, 6, DATA_OFFSET, DATA_ADDRESS, 0x1000, 0x1000, 0x4000),
            (PT_DYNAMIC, 6, DYNLIB_OFFSET + DYNAMIC, 0, len(tags) * 16, len(tags) * 16, 8),
            (PT_SCE_DYNLIBDATA, 4, DYNLIB_OFFSET, 0, 0x1000, 0x1000, 0x10),
            (PT_SCE_COMMENT, 0, 0, 0, 0, 0, 1),
            (PT_SCE_VERSION, 0, 0, 0, 0, 0, 1),
        ]
        if standard_tables:
            headers.append((PT_LOAD, 4, DYNLIB_OFFSET, DYNLIB_ADDRESS, 0x1000, 0x1000, 0x4000))
        if procparam:
            struct.pack_into("<QIIQ", data, DATA_OFFSET, 0x50, 0x4942524F, 3, 0x05050031)
            headers.append((PT_SCE_PROCPARAM, 4, DATA_OFFSET, DATA_ADDRESS, 0x50, 0x50, 8))
        if interpreter:
            data[TEXT_OFFSET + 0x800:TEXT_OFFSET + 0x800 + len(INTERPRETER)] = INTERPRETER
            headers.append((PT_INTERP, 4, TEXT_OFFSET + 0x800, 0x800, len(INTERPRETER), len(INTERPRETER), 1))
        headers += [(PT_SCE_VERSION, 0, 0, 0, 0, 0, 1)] * 3
    struct.pack_into("<HHIQQQIHHHHHH", data, 16,
                     elf_type, 62, 1, ENTRY, 64, 0, 0, 64, 56, len(headers), 64, 0, 0)
    for index, (kind, flags, offset, address, file_size, memory_size, alignment) in enumerate(headers):
        struct.pack_into("<IIQQQQQQ", data, 64 + index * 56,
                         kind, flags, offset, address, address, file_size, memory_size, alignment)
    return data


def eboot(elf_type=0xFE10, relocations=None, **options):
    strings = Strings()
    provider_file = strings.add("libProvider.prx")
    provider = strings.add("libProvider")
    tags = [(DT_NEEDED, provider_file),
            (DT_SCE_NEEDED_MODULE, module_value(1, provider)),
            (DT_SCE_IMPORT_LIB, library_value(0, provider)),
            (DT_SCE_IMPORT_LIB_ATTR, 9),
            (DT_SCE_MODULE_INFO, module_value(0, strings.add("eboot"))),
            (DT_SCE_MODULE_ATTR, 0),
            (DT_SCE_ORIGINAL_FILENAME, strings.add("eboot.bin"))]
    if relocations is None:
        relocations = [(RELRO_ADDRESS + 0x20, 8, ENTRY)]
    return image(elf_type, CHECK_IMPORT, tags, [(IMPORT + "#A#B", 0x12, 0, 0, 0)], strings,
                 relocations=relocations, plt=[(GOT_SLOT, (1 << 32) | 7, 0)],
                 procparam=True, interpreter=True, **options)


def provider_module(flags=4):
    strings = Strings()
    name = strings.add("libProvider")
    tags = [(DT_SCE_MODULE_INFO, module_value(0, name)),
            (DT_SCE_EXPORT_LIB, library_value(0, name)),
            (DT_SCE_EXPORT_LIB_ATTR, 9),
            (DT_SCE_MODULE_ATTR, 0)]
    data = image(0xFE18, PROVIDE_42, tags, [(IMPORT + "#A#A", 0x12, 1, ENTRY, len(PROVIDE_42))], strings,
                 relocations=[(RELRO_ADDRESS, 8, ENTRY)])
    flags_entry = data.index(struct.pack("<qQ", DT_FLAGS, 4))
    struct.pack_into("<qQ", data, flags_entry, DT_FLAGS, flags)
    return data


def program_headers(data):
    offset, = struct.unpack_from("<Q", data, 32)
    size, count = struct.unpack_from("<HH", data, 54)
    return [struct.unpack_from("<IIQQQQQQ", data, offset + index * size) for index in range(count)]


def dynamic_entries(data):
    headers = program_headers(data)
    dynamic = next(header for header in headers if header[0] == PT_DYNAMIC)
    loads = [header for header in headers if header[0] == PT_LOAD]

    def offset(address):
        for header in loads:
            if header[3] <= address < header[3] + header[5]:
                return header[2] + address - header[3]
        raise AssertionError(f"Unmapped address: {address:#x}")

    tags = []
    for position in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from("<qQ", data, position)
        if tag == 0:
            break
        tags.append((tag, value))
    strings = offset(next(value for tag, value in tags if tag == 5))
    symbols = offset(next(value for tag, value in tags if tag == 6))

    def string(value):
        return data[strings + value:data.index(0, strings + value)].decode()

    return tags, string, symbols, offset


def main():
    relinker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="orbridge-ps4-executable-") as directory:
        work = Path(directory)

        def convert(name, executable, modules=None, options=()):
            case = work / name
            case.mkdir()
            source = case / "eboot.bin"
            source.write_bytes(executable)
            if modules is None:
                options = ("--skip-sce-module", *options)
            else:
                (case / "sce_module").mkdir()
                for filename, data in modules.items():
                    (case / "sce_module" / filename).write_bytes(data)
            output = case / "eboot.elf"
            result = subprocess.run([str(relinker), *options, str(source), str(output)],
                                    capture_output=True, text=True, timeout=30)
            return result, output

        def fails(name, executable, message, modules=None, options=()):
            result, output = convert(name, executable, modules, options)
            assert result.returncode == 2 and message in result.stderr and not output.exists(), (
                name, result.returncode, result.stdout, result.stderr)

        result, output = convert("linux", eboot(), {"libProvider.prx": provider_module()})
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert "Detected guest platform: PS4 (DT_SCE_NEEDED_MODULE 0x6100000f)" in result.stdout, result.stdout
        relinked = output.read_bytes()
        headers = program_headers(relinked)
        assert not any(header[0] == PT_SCE_RELRO for header in headers), headers
        assert any(header[0] == PT_LOAD and header[3] == RELRO_ADDRESS and header[1] & 2 for header in headers), headers
        interpreters = [relinked[header[2]:header[2] + header[5]] for header in headers if header[0] == PT_INTERP]
        assert interpreters == [b"/lib64/ld-linux-x86-64.so.2\0"], interpreters
        assert any(header[0] == PT_SCE_PROCPARAM and header[3] == DATA_ADDRESS for header in headers), headers
        tags, string, symbols, _ = dynamic_entries(relinked)
        needed = [string(value) for tag, value in tags if tag == DT_NEEDED]
        assert needed == ["$ORIGIN/app0/sce_module/libProvider.prx.guest.prx"], needed
        assert string(struct.unpack_from("<I", relinked, symbols + 24)[0]) == IMPORT + "#guest"
        module = output.parent / "app0" / "sce_module" / "libProvider.prx.guest.prx"
        module_headers = program_headers(module.read_bytes())
        assert any(header[0] == PT_LOAD and header[3] == RELRO_ADDRESS and header[1] & 2 for header in module_headers), module_headers
        if sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64"):
            output.chmod(0o755)
            executed = subprocess.run([str(output)], capture_output=True, timeout=20)
            assert executed.returncode == -signal.SIGTRAP, (executed.returncode, executed.stderr)

        result, output = convert("windows", eboot(), {"libProvider.prx": provider_module()}, ("--windows",))
        assert result.returncode == 0 and output.read_bytes().startswith(b"MZ"), (result.stdout, result.stderr)
        assert "Detected guest platform: PS4" in result.stdout, result.stdout

        fails("fixed-address", eboot(0xFE00),
              "PS4 fixed-address executables (ET_SCE_EXEC 0xfe00) are not supported")
        fails("shared-type", eboot(3), "Unsupported PS4 executable type 0x3; expected 0xfe10")
        fails("filtered", eboot(), "unused-filter=1 is not supported for PS4 executables", options=("unused-filter=1",))
        fails("strict-filtered", eboot(), "unused-filter=2 is not supported for PS4 executables", options=("unused-filter=2",))
        fails("text-relocation", eboot(relocations=[(ENTRY, 8, ENTRY)]),
              "text relocations are not supported")
        fails("executable-relro", eboot(relro_flags=5), "Executable PT_SCE_RELRO segment is not supported")

        no_dynlib = eboot()
        for index, header in enumerate(program_headers(no_dynlib)):
            if header[0] == PT_SCE_DYNLIBDATA:
                struct.pack_into("<I", no_dynlib, 64 + index * 56, PT_SCE_VERSION)
        fails("missing-dynlibdata", no_dynlib, "SCE DT_STRTAB requires a PT_SCE_DYNLIBDATA segment")

        short_dynlib = eboot()
        for index, header in enumerate(program_headers(short_dynlib)):
            if header[0] == PT_SCE_DYNLIBDATA:
                struct.pack_into("<QQ", short_dynlib, 64 + index * 56 + 32, STRTAB + 4, STRTAB + 4)
        fails("table-outside-dynlibdata", short_dynlib, "SCE DT_STRTAB exceeds PT_SCE_DYNLIBDATA")

        fails("module-flags", eboot(), "Unsupported guest dynamic flags",
              modules={"libProvider.prx": provider_module(0x14)})
    print("PS4 executable tests passed")


if __name__ == "__main__":
    main()
