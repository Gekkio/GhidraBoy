# Change Log

## [Unreleased]

### Changed

- Add support for Ghidra 11.3

## 20240929 - 2024-09-29

### Changed

- Build with Java 21
- Add support for Ghidra 11.2

## 20240711 - 2024-07-11

### Changed

- Add support for Ghidra 11.1.2

## 20240709 - 2024-07-09

### Changed

- Add support for Ghidra 11.1.1

## 20240609 - 2024-06-09

### Changed

- Build with Ghidra 11.1
- Drop support for older Ghidra versions due to decompiler behaviour change

## 20231227 - 2023-12-27

### Changed

- Build with Ghidra 11.0

## 20231006 - 2023-10-06

### Changed

- Build with Ghidra 10.4

## 20230830 - 2023-08-30

### Changed

- Build with Ghidra 10.3.3

## 20230718 - 2023-07-18

### Changed

- Build with Ghidra 10.3.2

## 20230511 - 2023-05-11

### Changed

- Build with Ghidra 10.3

## 20230420 - 2023-04-20

### Changed

- Build with Ghidra 10.2.3

### Fixed

- DAA pseudo op tracks data dependencies much better

## 20221116 - 2022-11-16

### Changed

- Build with Ghidra 10.2.2

### Fixed

- Revert unintended change in memory block order

## 20221115 - 2022-11-15

### Added

- Meaningful comments to all created memory blocks

### Changed

- Improve decompilation result when checking negative flags (NC, NZ)
- Build with Ghidra 10.2.1
- Build with Java 17

### Fixed

- Typo in ROM bank memory block comment
- Fix accidental generation of duplicate data types

## 20220521 - 2022-05-21

### Changed

- Build with Ghidra 10.1.4

## 20220510 - 2022-05-10

### Changed

- Build with Ghidra 10.1.3

## 20220316 - 2022-03-16

### Changed

- Build with Ghidra 10.1.2

## 20211211 - 2021-12-11

### Changed

- Build with Ghidra 10.1

## 20211028 - 2021-10-28

### Changed

- Build with Ghidra 10.0.4

## 20210817 - 2021-08-17

### Changed

- Build with Ghidra 10.0.2

## 20210728 - 2021-07-28

### Changed

- Build with Ghidra 10.0.1

## 20210630 - 2021-06-30

### Changed

- Build with Ghidra 10.0

## 20210529 - 2021-05-29

### Changed

- Build with Ghidra 9.2.4

## 20210418 - 2021-04-18

### Changed

- Build with Ghidra 9.2.3

## 20210120 - 2021-01-20

### Added

- Absolute offset as the comment in ROM memory banks. Note: this is done when importing a ROM, so existing projects won't automatically get the comments just by upgrading GhidraBoy

### Changed

- Build with Ghidra 9.2.2

## 20201223 - 2020-12-23

### Changed

- Build with Ghidra 9.2.1

## 20201113 - 2020-11-13

### Changed

- Build with Ghidra 9.2

## 20200219 - 2020-02-19

### Changed

- Build with Ghidra 9.1.2

## 20200122 - 2020-01-22

### Changed

- Build with Ghidra 9.1.1

### Fixed

- Fix INC (HL) and DEC (HL) behaviour. These were considered no-ops

## 20191104 - 2019-11-04

### Changed

- Build with Ghidra 9.1 final release

## 20190924 - 2019-09-24

### Fixed

- Fix compatibility with Ghidra 9.1 development version changes

## 20190803 - 2019-08-03

### Added

- Initial release for Ghidra 9.1 development version
