# lself

A command-line tool for listing and inspecting ELF files. It works similarly to `ls` but targets ELF binaries — it can scan directories, filter by architecture, type, linked libraries, or symbols, and display relevant ELF metadata.

## Features

- List ELF files from one or more paths
- Recursively scan directories
- Filter by architecture (x86, x86_64, arm, aarch64, ...)
- Filter by ELF type (executable, shared library, relocatable, core, ...)
- Filter by linked library
- Filter by symbol name and type (function, object, or any)
- Display architecture, type, and linked libraries per file
- Colorized output
- Bash completion support
- Configuration file support (`~/.lselfrc`)

## Usage

```
lself [options] <input paths...>
```

### Options

| Option | Description |
|---|---|
| `-l<lib>`, `--lib <lib>` | Filter by linked library (e.g., `-lfoo`, `--lib libfoo`) |
| `-a`, `--arch <arch>` | Filter by architecture (e.g., `x86`, `x86_64`, `arm`, `aarch64`) |
| `-t`, `--type <type>` | Filter by ELF type (see types below) |
| `-s`, `--symbol <t:?sym>` | Filter by symbol name, optionally with type prefix |
| `--strict` | Only match the exact type (don't treat `ET_EXEC` as matching `ET_DYN` and vice versa) |
| `-T`, `--test` | Test mode: return 0 if all inputs are valid ELF files |
| `-R`, `--recursive` | Recursively search directories |
| `-d`, `--depth <n>` | Set recursion depth (default: 1) |
| `-I`, `--ignore <pattern>` | Ignore files matching a wildcard pattern |
| `-L`, `--list` | Print in list format |
| `-P`, `--full-path` | Print relative path instead of just filename |
| `--real-path` | Print real (resolved) path |
| `-F`, `--pretty` | Pretty format (only with `--list`) |
| `--no-color` | Disable colorized output |
| `-1` | Print only the filename (no path) |
| `--show-arch=y\|n` | Show architecture in output (default: yes) |
| `--show-type=y\|n` | Show ELF type in output (default: yes) |
| `--show-libs=y\|n\|m` | Show linked libraries (default: yes; `m` = only if matching filter) |
| `--show-symbols=y\|n\|m` | Show symbols (default: no; `m` = only if matching filter) |
| `-v`, `--verbose` | Enable verbose output |
| `--config <file>` | Use specified config file |
| `--no-config` | Don't load `~/.lselfrc` |
| `--version` | Show version information |
| `-h`, `--help` | Show help message |

### ELF Types

| Value | Description |
|---|---|
| `relocatable`, `rel`, `r` | Relocatable object file |
| `executable`, `exec`, `e` | Executable file |
| `dynamic`, `dyn`, `d` | Dynamically linked file |
| `shared`, `s` | Shared library |
| `core`, `c` | Core dump |
| `all`, `a` | Any type |

### Symbol Types (for `--symbol`)

| Prefix | Description |
|---|---|
| `func:`, `f:` | Function symbol |
| `object:`, `obj:`, `o:` | Object symbol |
| `any:`, `a:` | Any symbol type |

**Examples:**
```sh
# Show all ELF files in /usr/bin
lself /usr/bin

# Show ELF files in /usr/bin in list mode (elf type, elf machine, file name)
lself /usr/bin -L

#Show ELF files in List mode using pretty format
self /usr/bin/openssl /usr/bin/ssh -L --pretty

# List 64-bit executables linked against libpthread
lself --arch x86_64 --type exec --lib libpthread /usr/bin

#Or short for library (like in C linker)
lself --arch x86_64 --type exec -lpthread /usr/bin

# Recursively find shared libraries containing a function named "malloc"
lself -R --type shared --symbol func:malloc /usr/lib

# Test if a file is a valid ELF
lself --test ./mybinary
```

## Building

### Requirements

- GCC (or any C compiler)
- `make`
- Standard C library with ELF headers (`<elf.h>`)

### Build

```sh
make
```

This builds the `lself` binary and the `lself_completion.bash` autocompletion script using a static `libelfctx.a` by default.

#### Build options

| Variable | Default | Description |
|---|---|---|
| `RELEASE` | `1` | Set to `0` for a debug build (`-Og -g`) |
| `USE_SHARED_LIBS` | `0` | Set to `1` to build and link against `libelfctx.so` instead of the static library |
| `PREFIX` | `/usr` | Installation prefix |
| `EXECUTABLE` | `lself` | Name of the output binary |
| `V` | `0` | Set to `1` for verbose build output |

Example — debug build:
```sh
make RELEASE=0
```

Example — build with shared library:
```sh
make USE_SHARED_LIBS=1
```

### Install

```sh
#Only for PREFIX=/usr, run without sudo if you have the permissions to install to the target path
sudo make install 
```

Installs:
- `lself` binary to `$(PREFIX)/bin/ -> default: /usr/bin`
- `lself_completion.bash` to `$(PREFIX)/share/bash-completion/completions/lself -> default: /usr/share/bash-completion/completions/lself`
- `libelfctx.so` to `$(PREFIX)/lib/` (only when `USE_SHARED_LIBS=1`)

Custom prefix example:
```sh
sudo make install PREFIX=/usr/local
```

### Clean

```sh
make clean
```

## Bash Completion

After installing, reload your shell or source the completion script manually:

```sh
source /usr/share/bash-completion/completions/lself
```

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.
