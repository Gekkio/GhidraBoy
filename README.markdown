# GhidraBoy: Sharp SM83 / Game Boy extension for Ghidra

**Very experimental! No compatibility guarantees!**

Supported Ghidra versions:

- 11.3
- 11.2
- 11.1.2
- 11.1.1
- 11.1

![Tetris disassembly](screenshot.png)

## Features

* Sharp SM83 (CPU core used in Game Boy) support for Sleigh
* Game Boy ROM loader:
  - Can load unbanked ROMs (&lt;= 32kB, e.g. Tetris)
  - Can load banked ROMs (&gt; 32kB, e.g. Pokemon)
  - Can load greyscale boot ROMs (DMG/DMG0/MGB/SGB/SGB2)
  - Can load color boot ROMs (CGB/CGB0)
* Memory blocks based on the hardware memory map
  - Banked regions use overlays (TODO: figure out if there's a better way to
    support them)
  - GB vs GBC differences are handled (e.g. banked WRAM)
- Symbols for hardware registers (0xFFxx range)
  - GB vs GBC differences are handled (e.g. existence of KEY1 register)
* Game Boy cartridge header data types
  - Enumerated types for some things

## How to install

1. Download a [prebuilt GhidraBoy release](https://github.com/Gekkio/GhidraBoy/releases), or build it yourself.
2. Start Ghidra
3. File -> Install Extensions
4. Press the plus icon ("Add extension")
5. Choose the built or downloaded GhidraBoy zip file
6. Restart Ghidra when prompted to load the extension properly

## How to build

As a prerequisite, you need to have a Ghidra installation somewhere (an actual
installation, not a copy of Ghidra source code!).

```
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

or

```
./gradlew -Pghidra.dir=/path/to/ghidra
```

You can then find a built extension .zip in the `build/distributions` directory.

## Open questions / problems

- Decompiler output is difficult to read if certain instructions are used (e.g.
  rotates, JP HL for jumptables)
- Default "ASM calling convention" assumes all registers can be inputs and/or
  outputs. Inputs/outputs are often guessed incorrectly, so manual tuning is
  required for almost every function
- Are overlays the only / the best solution for handling banked memory areas?
  Right now in banked ROMs every function call to 0x4000-0x7fff needs to be
  manually resolved to the correct bank(s)

## License

Licensed under the Apache License, Version 2.0.
