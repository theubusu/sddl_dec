#!/usr/bin/python3

from Crypto.Cipher import AES
import os
import sys
import os.path
import struct
import zlib
import shutil
from tqdm import tqdm
import tarfile

noTempDelete = False

if len(sys.argv) < 2:
    print("Usage: python sddl_dec.py <SDDL.SEC file> (-n)")
    print("\nThe -n option will make the script not delete the temp folder.")
    sys.exit(1)

input_file = sys.argv[1]

if len(sys.argv) > 2:
    if sys.argv[2] == '-n':
        noTempDelete = True

with open('./crypto_key', 'rb') as f:
    key_buf = bytearray(f.read())
with open(input_file, 'rb') as f:
    sddl_buf = bytearray(f.read())

def decipher(b: bytearray):
    assert len(b)<0x7f # (later complex logic is not reversed)
    acc = 0x388
    for i in range(len(b)):
        new_acc = 0x96a3 + (acc + key_buf[i])
        b[i] ^= 0xff & (acc >> 8)
        acc = new_acc
        
def decipher_2(s, len_):
    v3 = 904
    out = bytearray(s)
    cnt = 0
    while len_ > 0:
        if len_ >= 0x80:
            true_len = 128
        else:
            true_len = len_
        if true_len:
            i = 0
            j = 0
            while i < len(s):
                iter_ = s[i]
                i += 1
                j = (j + 1) & 0xff
                v11 = iter_ + 38400
                v11 = v11 & 0xffffffff
                v12 = iter_ ^ ((v3 & 0xff00) >> 8)
                v3 += v11 + 163
                v3 = v3 & 0xffffffff
                if j == 0:
                    v3 = 904
                # out += bytes([v12])
                out[cnt] = v12
                cnt += 1
        len_ -= true_len
        return out


decipher(key_buf)

key = key_buf[:16]
iv = key_buf[16:]

print("sddl_dec Tool Version 1.0")

# print(repr(key), repr(iv))

def decrypt_payload(b):
    cip = AES.new(key, AES.MODE_CBC, iv)
    return cip.decrypt(b)
def decrypt_payload_unpad(b): 
    b1 = decrypt_payload(b)
    return b1[:-b1[-1]]

os.makedirs('sddldec_temp', exist_ok=True)
    
print("(1/3) Extracting...")

off = 0x20
total_parts = -1
while off < len(sddl_buf)-0x80:
    hdr = decrypt_payload_unpad(sddl_buf[off:off+0x20])
    file_name = hdr.split(b'\0')[0]
    file_size = int(hdr[16:].decode())
    file_content = sddl_buf[off+0x20:off+0x20+file_size]
    off += 0x20 + file_size
    print('Saved part: ', file_name, file_size)
    if file_name.startswith(b'PEAKS.F'):
        total_parts += 1
    filenm = os.path.join('sddldec_temp', file_name.decode())
    with open(filenm, 'wb') as f:
        f.write(decrypt_payload_unpad(file_content))

total_parts += 1
    
print("Total parts: " + str(total_parts))
        
print("(2/3) Decompressing...")
        
for i in tqdm(range(total_parts)):
    out_f = open(f"sddldec_temp/PEAKS.F{i:02}.out", "wb")
    in_f = open(f"sddldec_temp/PEAKS.F{i:02}" , "rb")
    in_f.read(0x20)
    number = struct.unpack(">H", in_f.read(0x2))[0]
    control = struct.unpack(">H", in_f.read(0x2))[0]
    data_size = struct.unpack(">I", in_f.read(0x4))[0]
    decrypt_size = struct.unpack(">I", in_f.read(0x4))[0]
    unzlib_crc = struct.unpack(">I", in_f.read(0x4))[0]
    data = in_f.read()
    assert len(data) == data_size
    decrypt_data = decipher_2(data, len(data))
    if decrypt_data.startswith(b'\x01'):
        out_f.write(decrypt_data)
        print("\nSkipped uncompressed file " + str(i))
    else:
        out_f.write(zlib.decompress(decrypt_data, zlib.MAX_WBITS))
    out_f.flush()
    out_f.close()
    in_f.close()

print("\nDetecting mode...")

with open('sddldec_temp/PEAKS.F00.out', errors="ignore") as f:
    if 'DLDATA_LIST.TXT' in f.read():
        seek_val = 0x10E
        print("Continue with tgz mode...")
        mode = 1
    else:
        seek_val = 0xE
        print("Continue with normal mode...")
        mode = 2

print("\n(3/3) Combining...")

if mode == 1:
    output_file='root.tgz'
else:
   output_file='out.bin'

def merge():
    combined_data = bytearray()

    for i in tqdm(range(1, total_parts)):
        filename = f"sddldec_temp/PEAKS.F{i:02d}.out"
        try:
            with open(filename, 'rb') as f:
                f.seek(seek_val)
                section = f.read()
                combined_data.extend(section)
        except FileNotFoundError:
            print(f"File not found: {filename}")
        except Exception as e:
            print(f"Error processing {filename}: {e}")

    with open(output_file, 'wb') as out_file:
        out_file.write(combined_data)
        print(f"\nExtracted data written to {output_file}")

merge()

if noTempDelete == False:
    print("Deleting temp files...")
    if os.path.exists('sddldec_temp'):
        shutil.rmtree('sddldec_temp')
    else:
        print(f"Temp folder does not exist.")

print("Script done.")