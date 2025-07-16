from Crypto.Cipher import AES
import os
import struct
import zlib
import argparse

def decrypt_payload(key, iv, b):
    cip = AES.new(key, AES.MODE_CBC, iv)
    return cip.decrypt(b)
    
def decrypt_payload_unpad(key, iv, b):
    b1 = decrypt_payload(key, iv, b)
    return b1[:-b1[-1]]

# https://nese.team/posts/justctf
# decipher the obfuscated key file
def decipher_key_file(b: bytearray):
    assert len(b)<0x7f # (later complex logic is not reversed)
    acc = 0x388
    for i in range(len(b)):
        new_acc = 0x96a3 + (acc + b[i])
        b[i] ^= 0xff & (acc >> 8)
        acc = new_acc

# https://nese.team/posts/justctf
# deciphering function for file contents
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

def read_sddl(input_file, crypto_key_file, output_folder):
    print("Input file: ", input_file)
    with open(input_file, 'rb') as f:
        sddl_buf = bytearray(f.read()) 
       
    print("Key file: ", crypto_key_file)    
    with open(crypto_key_file, 'rb') as f:
        key_buf = bytearray(f.read())
        
    decipher_key_file(key_buf)
    key = key_buf[:16]
    iv = key_buf[16:]
    
    #initial offset = lenght of SDDL.SEC file header(0x20)
    off = 0x20
    
    while off < len(sddl_buf)-0x80:
        #read header of entry with 0x20 lenght and decrypt it
        hdr = decrypt_payload_unpad(key, iv, sddl_buf[off:off+0x20])
        #read null-terminated string - file name
        file_name = hdr.split(b'\0')[0]
        #read from byte 16 - file size as ASCII
        try:
            file_size = int(hdr[16:].decode())
        except ValueError as e:
            print("!!Decryption error!! This file and key are not compatible!")
            return
        #read the files' content from buf with the read file size
        file_content = sddl_buf[off+0x20:off+0x20+file_size]
        #advancing the offset for next file
        off += 0x20 + file_size
        print('File: ' + file_name.decode("utf-8") + " Size: " + str(file_size))
        filenm = file_name.decode()
        
        if extract:
            if not os.path.exists(output_folder):
                os.makedirs(output_folder)
        
            decrypted_data = decrypt_payload_unpad(key, iv, file_content)
            if decrypted_data.startswith(b'\x11\x22\x33\x44') and not filenm == "SDIT.FDI": #header of obfuscated file, SDIT.FDI also has this header but seems to work differently so its skipped
                print("- Deciphering file...")
                #size of data after decryptiom
                data_size = struct.unpack('>I', decrypted_data[36:40])[0]
                #verify the data size
                assert len(decrypted_data[48:]) == data_size
                decipher_data = decipher(decrypted_data[48:], len(decrypted_data[48:]))
                if decipher_data.startswith(b'\x78\x9C'):
                    #decompress a compressed file
                    print("-- Decompressing file...")
                    out_data = zlib.decompress(decipher_data, zlib.MAX_WBITS)      
                else:
                    #file is not compressed, write raw data.
                    print("-- Skipping uncompressed file...")
                    out_data = decipher_data

                file_offset = struct.unpack(">I", b'\x00' + out_data[6:9])[0]
                #print("OFFSET: " + str(hex(file_offset)))
                
                if filenm.startswith("PEAKS.F") and join_peaks:
                    output_path = os.path.join(output_folder, "PEAKS.bin")
                    with open(output_path, "ab") as f:
                        f.write(out_data[file_offset:])
                    print("--- Appended to PEAKS.bin!")
                else:
                    output_path = os.path.join(output_folder, filenm)
                    with open(output_path, 'wb') as f:
                        f.write(out_data[file_offset:])
                    print("--- Saved file!")
            else:
                if filenm.endswith(".TXT") and skip_txt:
                    print(decrypted_data.decode())
                else:
                    output_path = os.path.join(output_folder, filenm)
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    print("- Saved file!")
    if extract:
        print("\nScript done! Saved extracted files to ", output_folder)
    else:
        print("\nScript done!")

if __name__ == "__main__":
    print("sddl_dec Tool Version 3.0")
    parser = argparse.ArgumentParser(description='sddl_dec Tool Version 3.0')
    
    parser.add_argument('-l', action='store_true', help='List the files but dont extract them.')
    parser.add_argument('-nj', action='store_true', help='Dont join PEAKS.F files.')
    parser.add_argument('-kt', action='store_true', help='Keep .TXT files from the SDDL.SEC file.')
    parser.add_argument('input_file', help='SDDL.SEC file to decrypt.')
    parser.add_argument('crypto_key_file', help='Key to decrypt the file.')
    parser.add_argument('output_folder', nargs="?", default="out", help='Folder to save output files to.')
    args = parser.parse_args()
    
    extract = not args.l
    join_peaks = not args.nj
    skip_txt = not args.kt

    read_sddl(args.input_file, args.crypto_key_file, args.output_folder) 
