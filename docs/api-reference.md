# RECLI - Complete API Documentation

Based on the recli project structure from GitHub, here's the complete API documentation including all commands and modules:

## Table of Contents
1. [Core Components](#core-components)
2. [Analysis Modules](#analysis-modules)
   - [String Analysis](#string-analysis)
   - [Binary Analysis](#binary-analysis)
   - [Code Analysis](#code-analysis)
   - [Memory Analysis](#memory-analysis)
   - [Patching](#patching)
   - [Scanning](#scanning)
3. [Utility Functions](#utility-functions)
4. [Command Reference](#command-reference)

## Core Components

### CommandLineInterface

#### Description
Main CLI handler that processes commands and dispatches to modules.

#### Methods
```cpp
CommandLineInterface(int argc, char* argv[])
```
Initializes CLI with command line arguments.

```cpp
int run()
```
Executes the requested command.

```cpp
void register_commands()
```
Registers all available commands and their handlers.

### BinaryData

#### Description
Handles binary file loading and parsing using LIEF.

#### Methods
```cpp
BinaryData(const std::string& file_path)
```
Loads and parses binary file.

```cpp
bool is_valid() const
```
Checks if binary was loaded successfully.

```cpp
std::vector<Section> get_sections() const
```
Returns binary sections.

## Analysis Modules

### String Analysis

#### `strings` Command
Extracts strings from binary with various options.

**Options:**
- `--min-length`: Minimum string length (default: 4)
- `--unicode`: Scan for Unicode strings
- `--wide`: Scan for wide character strings
- `--encoding`: Specify custom encoding

**Methods:**
```cpp
StringExtractor::find_ascii_strings()
```
Finds ASCII strings in binary.

```cpp
StringExtractor::find_unicode_strings()
```
Finds Unicode strings in binary.

### Binary Analysis

#### `headers` Command
Displays binary header information.

**Options:**
- `--verbose`: Show detailed header info

#### `sections` Command
Lists binary sections with details.

**Options:**
- `--perms`: Show section permissions
- `--raw`: Show raw section data

### Code Analysis

#### `disasm` Command
Disassembles binary code.

**Options:**
- `--section`: Specific section to disassemble
- `--count`: Number of instructions to show
- `--arch`: Target architecture

#### `cfg` Command
Generates control flow graph.

**Options:**
- `--function`: Specific function to analyze
- `--format`: Output format (dot, png, svg)
- `--output`: Output file path

### Memory Analysis

#### `memory` Command
Analyzes memory layout and mappings.

**Options:**
- `--verbose`: Show detailed memory info
- `--regions`: Show memory regions

#### `dump` Command
Dumps memory regions or functions.

**Options:
- `--address`: Start address to dump
- `--size`: Size of region to dump
- `--function`: Function to dump

### Patching

#### `patch` Command
Patches binary at specified offsets.

**Options:**
- `--offset`: Offset to patch
- `--bytes`: New bytes to write
- `--string`: String to write
- `--backup`: Create backup file

### Scanning

#### `scan` Command
Scans binary with YARA rules.

**Options:**
- `--rules`: Path to YARA rules file
- `--quick`: Perform quick scan
- `--threads`: Number of threads to use

#### `sig` Command
Scans for known signatures.

**Options:**
- `--db`: Path to signature database
- `--update`: Update signature database

## Utility Functions

### File Utilities
```cpp
read_file(const std::string& path)
```
Reads file contents.

```cpp
write_file(const std::string& path, const string& content)
```
Writes content to file.

### Formatting Utilities
```cpp
format_hex(uint64_t value, int width = 8)
```
Formats value as hex string.

```cpp
format_disassembly(const cs_insn* insn)
```
Formats disassembled instruction.

## Command Reference

### Basic Commands
| Command | Description | Options |
|---------|-------------|---------|
| `help` | Show help message | |
| `version` | Show version info | |
| `info` | Show binary info | `--verbose` |

### Analysis Commands
| Command | Description | Options |
|---------|-------------|---------|
| `strings` | Extract strings | `--min-length`, `--unicode` |
| `headers` | Show headers | `--verbose` |
| `sections` | List sections | `--perms`, `--raw` |
| `imports` | Show imports | `--verbose` |
| `exports` | Show exports | `--verbose` |

### Disassembly Commands
| Command | Description | Options |
|---------|-------------|---------|
| `disasm` | Disassemble code | `--section`, `--count` |
| `cfg` | Control flow graph | `--function`, `--format` |
| `xref` | Find references | `--address`, `--function` |

### Advanced Commands
| Command | Description | Options |
|---------|-------------|---------|
| `patch` | Patch binary | `--offset`, `--bytes` |
| `scan` | YARA scan | `--rules`, `--quick` |
| `sig` | Signature scan | `--db`, `--update` |
| `fuzz` | Fuzz testing | `--iterations`, `--seed` |

### Memory Commands
| Command | Description | Options |
|---------|-------------|---------|
| `memory` | Memory map | `--verbose` |
| `dump` | Dump memory | `--address`, `--size` |
| `trace` | Trace execution | `--function`, `--count` |

