# laZzzy Dump

A static analysis tool for extracting encrypted shellcode from laZzzy-wrapped PE binaries without requiring dynamic execution, debugging, or emulation.

## Overview

laZzzy Dump is a malware analysis tool which aids analysis through static extraction of shellcode from binaries compiled with [laZzzy](https://github.com/capt-meelo/laZzzy), an open-source shellcode loader that uses AES-CBC encryption combined with XOR obfuscation.

During incident response investigations involving multi-stage malware chains, manually decrypting laZzzy payloads is tedious and time-consuming. This tool automates the process by:

1. **Locating the decryption routine** via byte-pattern signature matching
2. **Extracting cryptographic material** (AES key, IV, ciphertext) using RIP-relative address resolution
3. **Decrypting offline** using standard AES-CBC followed by XOR deobfuscation

## How It Works

laZzzy produces a complete Windows PE executable that includes:

- An AES-CBC encrypted shellcode payload
- An AES decryption routine with a distinctive compiled signature
- RIP-relative addressing to locate key material and ciphertext in memory

### Signature Matching

The AESDecrypt function compiled by laZzzy contains a recognizable instruction sequence:

- AES initialization 
- RCX loading for context setup 
- RDX loading for XOR key 
- R8D loading for payload size 
- Decryption call 
- XOR post-processing 
- Stack teardown and return

The tool scans the binary for this pattern and locates the function without requiring a disassembler.

### Address Resolution

Once the function is found, the tool extracts operands from `LEA` and `MOV` instructions and resolves RIP-relative addresses to recover:

- **Key**: The AES key data (typically 16 or 32 bytes)
- **IV**: The initialization vector (16 bytes for AES-CBC)
- **XOR Key**: Additional XOR obfuscation layer (16 bytes)
- **Ciphertext**: The encrypted shellcode and its length

### Decryption

The extracted material is decrypted using:

1. **AES-CBC decryption** with the recovered key and IV
2. **XOR deobfuscation** using the XOR key (16-byte rolling XOR)

The result is the raw shellcode ready for further analysis.

## Installation

### Dependencies

```bash
pip install pefile pycryptodome
```

- **pefile**: PE binary parsing
- **pycryptodome**: AES-CBC decryption

## Usage

```bash
./laZzzy_dump.py -n <path_to_lazzy_binary>
```

### Example

```bash
./laZzzy_dump.py -n malware.exe
```

### Output

The tool prints:
- File offset and virtual address of the discovered AESDecrypt function
- AES key (hexdump format with offsets)
- Initialization vector (hexdump format)
- XOR key (hexdump format)
- Extracted shellcode to `<binary_path>_dumped`

## Example Output

```
[+] Processing malware.exe
[+] Found AESDecrypt function: Virtual Address:0x140026db0 File Offset:0x2db0
[+] Key: 
[+] 	0002f010  48 c2 f4 a1 12 34 56 78 9a bc de f0 11 22 33 44  |H..q...x......"3D|
[+] IV: 
[+] 	0002f020  55 66 77 88 99 aa bb cc dd ee ff 00 11 22 33 44  |Ufgw............"3D|
[+] XOR Key: 
[+] 	0002f030  aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99  |......"3DUfw....|
[+] Writing shellcode to malware.exe_dumped
```

## Limitations

- **laZzzy-specific**: Only extracts from PE binaries compiled with laZzzy
- **Signature-dependent**: Changes to laZzzy's compilation or obfuscation may break pattern matching
- **Static analysis only**: Does not require execution, but cannot handle obfuscated or variant instruction sequences
- **x86-64 only**: The byte-pattern signature assumes x86-64 compiled code

## Validation

The tool has been validated against multiple independently generated laZzzy samples with varying build configurations and payload types. The signature pattern successfully locates the AESDecrypt function across these samples without false positives.

## Related Tools

- [laZzzy](https://github.com/capt-meelo/laZzzy) - The shellcode loader being analyzed
- [Ghidra](https://ghidra-sre.github.io/) - Reverse engineering framework (used for validation)

## References

- laZzzy GitHub: https://github.com/capt-meelo/laZzzy
- AES-CBC: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC

## Disclaimer

This tool is provided for educational and authorized security research purposes only. Unauthorized access to computer systems is illegal. Use only on systems you own or have explicit permission to test.
