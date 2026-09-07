# 🛡️ C-Based Binary Analysis & PE Internals Utilities

This repository contains lightweight, zero-dependency C tools designed for **binary analysis, static triage, and Windows PE Internals learning**.

## 🛠️ Included Tools

### 1. PE Pattern Finder (`pe-pattern-finder.c`)
- Scans arbitrary binary files for `MZ` (DOS) and `PE\0\0` signatures using manual buffer scanning.
- Memory-safe buffer management with strict `fread`/`ftell` checks.

### 2. PE Header Parser (`pe-header-parser.c`)
- Parses DOS Headers, File Headers, and Section Headers directly from PE structures.
- Extracts architecture (`x86`, `x64`, `ARM64`), UTC Compilation Timestamps, and Section Flags.

### 3. PE Section Strings Extractor (`pe-section-strings-extractor.c`)
- Extracts both **ASCII** and **Windows Wide (UTF-16LE)** strings.
- **Section Mapping:** Maps detected string offset addresses directly to corresponding PE sections (`.text`, `.rdata`, `.idata`, etc.).
- Eliminates false positives in raw code spaces during static triage.
