from Crypto.Cipher import AES
import os
import struct
import zlib
import sys
from tqdm import tqdm

if len(sys.argv) < 2:
    print("sddl_dec Tool Version 2.0")
    print("Usage: python sddl_dec.py <SDDL.SEC file>")
    sys.exit(1)

input_file = sys.argv[1]

# Load files
with open('./crypto_key', 'rb') as f:
    key_buf = bytearray(f.read())
with open(input_file, 'rb') as f:
    sddl_buf = bytearray(f.read())
    
# decipher the obfuscated key file
def decipher_key_file(b: bytearray):
    assert len(b)<0x7f # (later complex logic is not reversed)
    acc = 0x388
    for i in range(len(b)):
        new_acc = 0x96a3 + (acc + key_buf[i])
        b[i] ^= 0xff & (acc >> 8)
        acc = new_acc
        
#AES-CBC decryption
def decrypt_payload(b):
    cip = AES.new(key, AES.MODE_CBC, iv)
    return cip.decrypt(b)
    
#decryption function + remove PKCS#7 padding
def decrypt_payload_unpad(b):
    b1 = decrypt_payload(b)
    return b1[:-b1[-1]]
    
# deciphering function
def decipher(s, len_):
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
        
print("sddl_dec Tool Version 2.0")

print("Deciphering key...")
                
# get key and iv from deciphered key
decipher_key_file(key_buf)
key = key_buf[:16]
iv = key_buf[16:]
#print(repr(key), repr(iv))
        
#initial offset = lenght of SDDL.SEC file header
off = 0x20

#go through the file until 0x80 till the end
with open("PEAKS.bin", "ab") as out_file:
    while off < len(sddl_buf)-0x80:

        #read header of entry with 0x20 lenght and decrypt it
        hdr = decrypt_payload_unpad(sddl_buf[off:off+0x20])
    
        #read null-terminated string - file name
        file_name = hdr.split(b'\0')[0]
    
        #read from byte 16 - file size as ASCII
        file_size = int(hdr[16:].decode())
    
        #read the files' content from buf with the read file size
        file_content = sddl_buf[off+0x20:off+0x20+file_size]
    
        #advancing the offset for next file
        off += 0x20 + file_size
    
        print('\nFound file: ' + file_name.decode("utf-8") + " Size: " + str(file_size))
        filenm = file_name.decode()

        #with open(filenm, 'wb') as f:
        #    f.write(decrypt_payload_unpad(file_content))
        
        #only extract PEAKS contents
        if filenm.startswith("PEAKS"):
    
            decrypted_data = decrypt_payload_unpad(file_content)
    
            #size of data after decryptiom
            data_size = struct.unpack('>I', decrypted_data[36:40])[0]
    
            # print("DATA SIZE: " + hex(data_size))
            
            #verify the data size
            assert len(decrypted_data[48:]) == data_size
        
            decipher_data = decipher(decrypted_data[48:], len(decrypted_data[48:]))
        
            if decipher_data.startswith(b'\x78\x9C'):
                #decompress a compressed file
                print("Decompressing...")
                out_data = zlib.decompress(decipher_data, zlib.MAX_WBITS)      
            else:
                #file is not compressed, write raw data.
                print("Skipping uncompressed file...")
                out_data = decipher_data
           
            #read the offset to be saved from the file
            file_offset = struct.unpack(">I", b'\x00' + out_data[6:9])[0]
        
            print("OFFSET: " + str(hex(file_offset)))
                        
            out_file.write(out_data[file_offset:])
            
            print('Appended file to PEAKS.bin: ', file_name)
            
        else:
            with open(filenm, 'wb') as f:
                f.write(decrypt_payload_unpad(file_content))
              
print("\nScript done. Saved extracted PEAKS data to PEAKS.bin")

