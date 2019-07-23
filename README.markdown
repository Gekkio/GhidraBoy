# GhidraBoy: Sharp SM83 / Game Boy extension for Ghidra

**Very experimental! No compatibility guarantees!**

Ghidra version: 9.1 (git master)

![Tetris disassembly](screenshot.png)

## How to build

```
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew
```

or

```
./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra
```

You can then find a built extension .zip in the `dist` directory.

## License

Licensed under the Apache License, Version 2.0.
