Memory Dump Analysis Test Files

This folder should contain memory dump files (.dmp, .raw, or similar)
captured from Windows or Linux systems for forensic analysis.

The Memory Analyzer will detect:
- Injected code and shellcode
- Malware signatures in memory
- Hidden processes
- Rootkit indicators
- Suspicious allocated memory regions
- API hooks
- DLL injection
- Process hollowing indicators

Sample test cases needed:
1. Clean memory dump - normal system memory with no malware
2. Infected memory dump - system with malware/trojan in memory
3. Rootkit memory dump - kernel-level rootkit indicators

To generate test memory dumps:
- Use Volatility framework to analyze real dumps
- WinDbg for Windows memory capture
- Memdump tools for Linux memory
- Or use prepared test dumps from security research

File formats supported: .raw, .dmp, .bin, .img
