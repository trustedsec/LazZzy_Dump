#!/usr/bin/env python
import re
import sys
import pefile
import argparse
from Crypto.Cipher import AES
from pathlib import Path

# Color code definitions
RED = '\033[31m'
GREEN = '\033[32m'
RESET = '\033[0m'

def print_i(msg):
    print(f'{GREEN}[+]{RESET} {msg}')

def print_e(msg):
    print(f'{RED}[!]{RESET} {msg}')

def hexdump(data: bytes, base_addr: int=0, chunk_size: int = 16):
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        
        # 1. Memory offset
        offset = f"{i+base_addr:08x}"
        
        # 2. Hex values grouped by spacing
        hex_string = " ".join(f"{b:02x}" for b in chunk)
        hex_string = hex_string.ljust(chunk_size * 3 - 1)
        
        # 3. Readable ASCII representation
        ascii_string = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        
        print_i(f"\t{offset}  {hex_string}  |{ascii_string}|")

def flip( x ):
   ret = b''
   for i in range(0,len(x),2):
       ret = x[i:i+2] + ret
   return ret


def aes_cbc_decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    return decrypted_padded

def decode( data, xor_key ):
    ret = b''
    for count in range(len(data)):
        tmp = data[count]^xor_key[count&0xf]
        ret += bytes([tmp])
    return ret

###########
#   0026d8 e8 63 ed ff ff  CALL  FUN_140001440_AES_init_ct undefined FUN_140
#   0026dd 48 8d 4c 24 20   LEA   RCX=>ctx,[RSP + 0x20]
#   0026e2 48 8d 15 27 f9 02  LEA   RDX,[DAT_140032010_xord_s = BDh
#   0026e9 41 b8 10 7f 06 00   MOV   R8D,0x67f10
#   0026ef e8 8c ee ff ff  CALL  FUN_140001580_AES_CBC_dec undefined FUN_140
#   0026f4 48 8b 8c 24 50 01   MOV   RCX,qword ptr [RSP + loca
#   0026fc 48 31 e1  XOR   RCX,RSP
#   0026ff e8 0c ca 02 00  CALL  FUN_14002f110             undefined FUN_140
def find_AESDecrypt(data):
    AES_ENCRYPT_reg  = b"\xe8 . . . .".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\x48 \x8d \x4c . ".replace(b' ', b'') + b'\x20'
    AES_ENCRYPT_reg += b"\x48 \x8d \x15 . . . .".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\x41 \xb8 . . . . ".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\xe8 . . . .".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\x48 \x8b \x8c . \x50 \x01 \x00 \x00 ".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\x48 \x31 \xe1 ".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\xe8 . . . .".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\x90".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\x48 \x81 \xc4 \x58 \x01 \x00 \x00".replace(b' ', b'')
    AES_ENCRYPT_reg += b"\xc3"

    matches = re.finditer(AES_ENCRYPT_reg, data)
    if not matches:
        return b""
    beginning = 0
    for match in matches:
        index = match.start()
        for i in range(0x100):
            if i > index:
                break
            ch = data[index-i]
            if ch == 0xcc:
                beginning =  index-i+1
                break
        if beginning:
            break
    for i in range(len(data[beginning:])):
        ch = data[beginning+i]
        if ch == 0xcc:
            end = beginning+i
            break
    return (beginning, data[beginning:end])
    
def get_data_info( function, index, pe):
    AES_ENCRYPT_reg = bytes.fromhex("41b8")+b"(....)"
    size = re.search(AES_ENCRYPT_reg, function)
    data_size = size.group(1)
    data_size = int.from_bytes(data_size[::-1], byteorder='big')
    tmp = function.index(size.group(0))

    offset = int.from_bytes( function[tmp - 4:tmp], byteorder='little')
    rva_mem_offset  = pe.get_rva_from_offset(index + tmp) # AESDecrypt offset + offset to current instruction
    t = rva_mem_offset + offset # Offset using RVA memory address plus offset
    data = pe.get_offset_from_rva(t) # Convert back to offset into the file
    return (data, data_size)

def get_offset_from_assembly(data):
    data = data[:-5:-1]
    return int.from_bytes(data, byteorder='big')

def get_key_iv( data, aes_code, index_aes, pe):
    reg = bytes.fromhex("488b05")+b"(....)"
    ret = {}
    ret['key'] = [0,b'']
    ret['iv'] = [0, b'']
    ret['xor_key'] = [0,b'']

    matches = re.finditer(reg, aes_code)
    if not matches:
        return b""

    f_data_addr = 0
    cnt = 0
    for match in matches:
        if cnt == 0:
            cnt += 1
            continue
        offset = get_offset_from_assembly(match.group(0))
        tmp = index_aes + match.span()[0]+7

        rva_mem_offset = pe.get_rva_from_offset(tmp)  # AESDecrypt offset + offset to current instruction
        t = rva_mem_offset + offset  # Offset using RVA memory address plus offset
        f_data_addr = pe.get_offset_from_rva(t)  # Convert back to offset into the file
        keyb = data[f_data_addr:f_data_addr+8]
        if cnt > 4:
            if ret['iv'][0] == 0:
                ret['iv'][0] = f_data_addr
            ret['iv'][1] += keyb
        else:
            if ret['key'][0] == 0:
                ret['key'][0] = f_data_addr
            ret['key'][1] += keyb
        cnt += 1

    ret['xor_key'][0] = f_data_addr + 8
    ret['xor_key'][1]  = data[f_data_addr+8:f_data_addr + 0x18]
    return ret

def main(filename):
    pe = pefile.PE(filename)
    imagebase = 0
    if hasattr(pe, 'OPTIONAL_HEADER'):
        imagebase = pe.OPTIONAL_HEADER.ImageBase

    index_AES = 0

    file_path = Path(filename)
    if not file_path.is_file():
        print_e("File not found")
        sys.exit(1)
    print_i(f"Processing {filename}")
    with open(filename, 'rb') as fd:
        data = fd.read()
        index_AES, aesDecrypt = find_AESDecrypt(data)
        if len(aesDecrypt) == 0 or index_AES == 0:
            print_e("Did not find the AESDecrypt function.")
            sys.exit(1)
        print_i(f"Found AESDecrypt function: Virtual Address:{hex(imagebase+ pe.get_rva_from_offset(index_AES))} File Offset:{hex(index_AES)}")
        data_offset, data_size = get_data_info(aesDecrypt, index_AES, pe)
        shellcode = data[data_offset:data_offset+data_size]

    key_iv = get_key_iv(data, aesDecrypt, index_AES, pe )
    print_i(f"Key: ")
    hexdump(key_iv['key'][1], base_addr=key_iv['key'][0] )
    print_i(f"IV: ")
    hexdump(key_iv['iv'][1], base_addr=key_iv['iv'][0] )
    print_i(f"XOR Key: ")
    hexdump(key_iv['xor_key'][1], base_addr=key_iv['xor_key'][0] )

    decrypted = aes_cbc_decrypt( shellcode, key_iv['key'][1], key_iv['iv'][1] )
    x = decode(decrypted, key_iv['xor_key'][1])
    print_i(f"Writing shellcode to {filename}_dumped")
    with open(filename+'_dumped','wb') as fd:
        fd.write(x)

def parse_args():
    parser = argparse.ArgumentParser(description='laZzzy shellcode extractor. Attempts to find the AESDecrypt function along with its key, iv and xor key.')
    parser.add_argument('-n', "--name", type=str, required=True, help="Name of the laZzy executable")
    return parser.parse_args()

if __name__=="__main__":
    args = parse_args()
    if hasattr(args, 'name'):
        main(args.name)
    else:
        args.print_help()

