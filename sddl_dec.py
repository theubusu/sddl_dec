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
    print("Input file:", input_file)
    with open(input_file, 'rb') as f:
        sddl_buf = bytearray(f.read()) 
       
    print("Key file:", crypto_key_file)    
    with open(crypto_key_file, 'rb') as f:
        key_buf = bytearray(f.read())
        
    decipher_key_file(key_buf)
    key = key_buf[:16]
    iv = key_buf[16:]
    
    #initial offset = lenght of SDDL.SEC file header(0x20)
    off = 0x20
    
    while off < len(sddl_buf):
        hdr = decrypt_payload_unpad(key, iv, sddl_buf[off:off+0x20])
        file_name = hdr.split(b'\0')[0]
        try:
            file_size = int(hdr[16:].decode())
        except ValueError as e:
            # SDDL files can have a footer(signature?) of 0x80 OR 0x100 lenght in later ones, and there is no good way to detect it before entering the while loop and the footer has no common header.
            # so we can assume if a file fails to decode at negative offsets 0x80 or 0x100, that is the footer and it can be skipped.
            if off == len(sddl_buf)-0x80:
                print("\nFound footer at 0x80 end!") 
                break
            if off == len(sddl_buf)-0x100:
                print("\nFound footer at 0x100 end!") 
                break
            else:
                print("!!Decryption error!! This file is not compatible!")
                return
                
        file_content = sddl_buf[off+0x20:off+0x20+file_size]
        off += 0x20 + file_size
        print('\nFile: ' + file_name.decode("utf-8") + " Size: " + str(file_size))
        filenm = file_name.decode()
        
        if extract:
            if not os.path.exists(output_folder):
                os.makedirs(output_folder)
        
            decrypted_data = decrypt_payload_unpad(key, iv, file_content)
            if decrypted_data.startswith(b'\x11\x22\x33\x44') and not filenm == "SDIT.FDI": #header of obfuscated file, SDIT.FDI also has this header but seems to work differently so its skipped   
                if verbose:
                    print("FILE HEADER:")
                    print("-ID:", decrypted_data[5])
                    if 8 <= decrypted_data[5] <= 20:
                        print("--Year guess:", decrypted_data[5] + 2003)
                    print("-BASE VERSION?:", decrypted_data[16:20])
                    print("-OLD VERSION:", decrypted_data[20:24])
                    print("-VERSION(NPKS):", decrypted_data[24:28])
                    print("1.BLOCK INDEX:", struct.unpack('>H', decrypted_data[32:34])[0])  #unused
                    print("2.CONTROL BYTES:", decrypted_data[34:36])
                    print("3.COMPRESSED SIZE:", struct.unpack('>I', decrypted_data[36:40])[0])
                    print("4.DECOMPRESSED SIZE:", struct.unpack('>I', decrypted_data[40:44])[0]) #unused
                    print("5.CHECKSUM:", decrypted_data[44:48]) #unused

                #file version
                version_major = decrypted_data[24]
                version_minor = int(f"{decrypted_data[25]}{decrypted_data[26]}{decrypted_data[27]}")
                print(f"- Version: {version_major}.{version_minor}")
                
                #control bytes
                control_bytes = decrypted_data[34:36]
                
                #size of data
                data_size = struct.unpack('>I', decrypted_data[36:40])[0]
                
                #verify the data size
                assert len(decrypted_data[48:]) == data_size

                print("- Deciphering file...")
                decipher_data = decipher(decrypted_data[48:], len(decrypted_data[48:]))
                
                if control_bytes.startswith(b'\x03'): #03 - file is compressed
                    #decompress a compressed file
                    print("-- Decompressing file...")
                    out_data = zlib.decompress(decipher_data, zlib.MAX_WBITS)      
                else: #02 - file is not compressed
                    #file is not compressed, write raw data.
                    print("-- Skipping uncompressed file...")
                    out_data = decipher_data
                
                dest_offset_bytes = bytearray(out_data[1:5])
                if dest_offset_bytes[0] & 0xF0 == 0xD0:
                    if verbose:
                        print("Pre2013 detected!")
                    dest_offset_bytes[0] &= 0x0F
                else:
                    if verbose:
                        print("2014+ detected!")
                        
                dest_offset = struct.unpack(">I", dest_offset_bytes)[0]        
                source_offset = struct.unpack(">I", b'\x00' + out_data[6:9])[0] #Safe trust me

                if verbose:
                    print("CONTENT HEADER:")
                    print("1.DEST OFFSET:", str(hex(dest_offset)))
                    print("2.SOURCE OFFSET:", str(hex(source_offset)))
                    print("3.SIZE:", struct.unpack(">I", out_data[9:13])[0])
                    
                if filenm.startswith("PEAKS.F") and join_peaks:
                    output_path = os.path.join(output_folder, "PEAKS.bin")
                    try:
                        f = open(output_path, "r+b")
                    except FileNotFoundError:
                        f = open(output_path, "w+b")
                    f.seek(dest_offset)
                    f.write(out_data[source_offset:])
                    print("--- Saved to PEAKS.bin!")
                else:
                    output_path = os.path.join(output_folder, filenm)
                    with open(output_path, 'wb') as f:
                        f.write(out_data[source_offset:])
                    print("--- Saved file!")
                
            else:
                if filenm.endswith(".TXT") and skip_txt:
                    print(decrypted_data.decode())
                else:
                    if filenm == "SDIT.FDI":
                        if verbose:
                            print("- NO OF ENTRIES:", decrypted_data[4])
                    output_path = os.path.join(output_folder, filenm)
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    print("- Saved file!")
    if extract:
        print("\nScript done! Saved extracted files to ", output_folder)
    else:
        print("\nScript done!")

if __name__ == "__main__":
    print("sddl_dec Tool Version 3.5 (22/08/2025)")
    parser = argparse.ArgumentParser(description='sddl_dec Tool Version 3.5')
    
    parser.add_argument('-l', action='store_true', help='List the files but dont extract them.')
    parser.add_argument('-v', action='store_true', help='Verbose mode - print detailed information about extraction process.')
    parser.add_argument('-nj', action='store_true', help='Dont join PEAKS.F files.')
    parser.add_argument('-kt', action='store_true', help='Keep .TXT files from the SDDL.SEC file.')
    parser.add_argument('input_file', help='SDDL.SEC file to decrypt.')
    parser.add_argument('crypto_key_file', help='Key to decrypt the file.')
    parser.add_argument('output_folder', nargs="?", default="out", help='Folder to save output files to.')
    args = parser.parse_args()
    
    extract = not args.l
    verbose = args.v
    join_peaks = not args.nj
    skip_txt = not args.kt

    read_sddl(args.input_file, args.crypto_key_file, args.output_folder) 
