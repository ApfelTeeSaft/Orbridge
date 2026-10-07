# About

Orbridge is a tool for automatic porting of PS4 and PS5 executables to Linux and Windows. It is a fork of [AnyPS5](https://github.com/boykopovar/AnyPS5) and extends its approach from PS5 executables to PS4 executables. The name combines Orbis and Southbridge.

Includes a [relinker](core/relinker) that converts executable to the target system's native format and implementations of [system prx libraries](core/libs/prx) suitable for dynamic linking. No emulation or separate runtime process: guest x86-64 code runs natively.

[Usage](docs/user/USAGE.md), [Build instructions](docs/dev/BUILD.md), [Technical debt of the project](docs/dev/TechnicalDebt.md), [code style conventions](docs/dev/CONVENTIONS.md), [contributing](CONTRIBUTING.md)

## Status

PS5: the relinker, system libraries, AGC driver and shader recompiler are inherited from AnyPS5. Upstream progress is published on the [AnyPS5 progress page](https://boykopovar.github.io/AnyPS5/) (upstream data, not Orbridge's).

PS4: experimental and in progress. The relinker detects PS4 executables and converts them and their bundled modules; this is verified with synthetic executables and with one title that relinks but does not start. The system libraries implement the PS5 interfaces, and the PS4 graphics stack (GNM driver, GCN shaders) is not implemented. No PS4 title runs yet.

Unsupported or unexpected states strictly throw `std::runtime_error`. `what()` is printed to stderr and the process terminates.

The [shader recompiler](core/shader/recompiler/Recompiler.cpp) produces SPIR-V from RDNA shaders (validated via [Spirv-Tools](3rdparty/SPIRV-Tools) when built with `ANYPS5_ENABLE_SPIRV_TOOLS`).

## Compatibility

See the [game compatibility list](docs/user/COMPATIBILITY.md) for tested games and known issues. PS4 titles are listed only once they have been tested.

## Input mapping

SDL-mapped game controllers are supported, including analog sticks and triggers. Keyboard and mouse controls can be configured with an `anyps5-input.ini` file. See [input mapping](docs/user/INPUT_MAPPING.md) for the supported devices and configuration format.

## Disclaimer

This project is intended for interoperability, research, preservation, and compatibility purposes. It does not include, distribute, or require copyrighted software, firmware, cryptographic keys, proprietary libraries or game binaries, and it does not decrypt SELF containers: the input must be a decrypted, clean ELF. Users are responsible for ensuring that any binaries used with this project are obtained and used in accordance with applicable laws and their respective license terms.

## License

This project is licensed under the GNU General Public License version 2 only.
