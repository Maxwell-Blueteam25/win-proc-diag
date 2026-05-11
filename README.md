# win-proc-diag
A low-level Windows process and security diagnostic utility.

### Overview

A C-based command-line tool for inspecting Windows process hierarchies, internal structures, and security contexts. It provides visibility into execution metadata typically restricted by process isolation.

### Features

* **Process Tree**: Full reconstruction of parent-child relationships.
* **PEB Parsing**: Extraction of raw command-line strings from the Process Environment Block.
* **Thread Inspection**: Enumeration of thread IDs and resolved thread descriptions.
* **Security Metadata**: Identification of Mandatory Integrity Levels (Low to System).

### Requirements

* Windows 10/11
* MinGW-w64 (GCC)
* Administrative privileges (required for `ReadProcessMemory` on high-integrity processes)

### Build

Compile using GCC, linking against `ntdll`:

```bash
gcc -o win-proc-diag.exe main.c -lntdll

```

### Usage

**View full system process tree:**

```bash
.\win-proc-diag.exe

```

**Inspect a specific PID:**

```bash
.\win-proc-diag.exe -pid <ID> -commandline true -threads true -integrity true

```

**Options:**

* `-pid <id>`: Target a specific process.
* `-commandline true`: Print the target's command-line arguments.
* `-threads true`: List target thread IDs and names.
* `-integrity true`: Show the process integrity RID.
* `--help`: Display help information.
