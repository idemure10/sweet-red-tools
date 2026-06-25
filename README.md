# sweet-red-tools
Educational Windows utilities for security research (VM lab only).
## Projects
### tool1_process_list
Lists running processes via WinAPI (CreateToolhelp32Snapshot, Process32First/Next).
Build: Visual Studio 2022, x64, Console.
### lab_loader
Demonstrates a minimal loader pipeline:
1. `encrypt_tool` — XOR-encrypt `payload.bin` → `payload_enc.bin`
2. `Resource.rc` — embed encrypted payload into `.rsrc`
3. `lab_loader` — extract resource, decrypt, print plaintext
**No shellcode, no execution, no injection.**
### parse_pe
PE file parser (console, read-only):
- DOS / NT headers (PE32 and PE32+)
- Section table
- Data directories
- Import table (DLLs and API names)
Build: Visual Studio 2022, x64, Console.
Run:
```text
parse_pe.exe <path_to_pe>
```
Example:
```text
parse_pe.exe C:\Windows\SysWOW64\cmd.exe
```
## Build lab_loader
1. Run `encrypt_tool` (updates `payload_enc.bin` if payload changed)
2. Build `lab_loader` (x64)
3. Run `lab_loader`
## Disclaimer
For learning only. Use isolated VM. Do not use against systems you do not own.