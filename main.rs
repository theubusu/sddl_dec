use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};

use aes::Aes128;
use clap::Parser;
use flate2::read::ZlibDecoder;
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};

type Aes128CbcDec = Decryptor<Aes128>;

/// Tool for decrypting and unpacking Panasonic TV SDDL.SEC update files. 
#[derive(Parser, Debug)]
struct Args {
    /// Show detailed information about extraction process.
    #[arg(short = 'v')]
    verbose: bool,

    /// Keep .TXT files
    #[arg(short = 'k')]
    keep_txt: bool,

    input_file: String,
    output_folder: String,
}

fn read_file(mut file: &File, offset: u64, size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; size];
    let _bytes_read = file.read(&mut buffer)?;

    Ok(buffer)
}

fn decrypt(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new(key.into(), iv.into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("!!Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}

//ported from original from https://nese.team/posts/justctf/
fn decipher(s: &[u8], len_: usize) -> Vec<u8> {
    let mut v3: u32 = 904;
    let mut out = s.to_vec();
    let mut cnt = 0;
    
    if len_ > 0 {
        let true_len = if len_ >= 0x80 {
            128
        } else {
            len_
        };
        
        if true_len > 0 {
            let mut i = 0;
            let mut j: u8 = 0;
            
            while i < s.len() {
                let iter_ = s[i];
                i += 1;
                j = j.wrapping_add(1);
                
                let v11 = (iter_ as u32).wrapping_add(38400) & 0xffffffff;
                let v12 = iter_ ^ ((v3 & 0xff00) >> 8) as u8;
                v3 = v3.wrapping_add(v11).wrapping_add(163) & 0xffffffff;
                
                if j == 0 {
                    v3 = 904;
                }
                
                if cnt < out.len() {
                    out[cnt] = v12;
                    cnt += 1;
                }
            }
        }
    }
    
    out
}

fn decompress_zlib(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    Ok(decompressed)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("sddl_dec Tool Version 4.0");
    let args = Args::parse();

    let file_path = args.input_file;
    println!("Input file: {}", file_path);

    let output_path = args.output_folder;
    println!("Output folder: {}", output_path);

    let verbose = args.verbose;
    let keep_txt = args.keep_txt;

    let file = File::open(file_path)?;
    let file_size = file.metadata()?.len();
    //println!("File size: {:?}", file_size);

    let key = [
        0x26, 0xE0, 0x96, 0xD3, 0xEF, 0x8A, 0x8F, 0xBB,
        0xAA, 0x5E, 0x51, 0x6F, 0x77, 0x26, 0xC2, 0x2C,
    ];
    
    let iv = [
        0x3E, 0x4A, 0xE2, 0x3A, 0x69, 0xDB, 0x81, 0x54,
        0xCD, 0x88, 0x38, 0xC4, 0xB9, 0x0C, 0x76, 0x66,
    ];

    let mut offset = 32;

    while offset < file_size {
        let header = read_file(&file, offset, 32)?;
        let decrypted_header: Vec<u8>; 

        match decrypt(&header, &key, &iv) {
            Ok(v) => decrypted_header = v,
            Err(_) => {
                // SDDL files can have a footer(signature?) of 0x80 OR 0x100 lenght in later ones, and there is no good way to detect it before entering the while loop and the footer has no common header.
                // so we can assume if a file fails to decode at negative offsets 0x80 or 0x100, that is the footer and it can be skipped.
                if offset == file_size - 128 {
                    if verbose{println!("Found footer at negative 0x80!");};
                    break
                } else if offset == file_size - 256 {
                    if verbose{println!("Found footer at negative 0x100!")};
                    break
                } else {
                    println!("!!Decryption error!! This file is invalid or not compatible!");
                    std::process::exit(0)
                }
            },
        }

        let decrypted_string = String::from_utf8_lossy(&decrypted_header);

        let filename = decrypted_string.split("\0").next().unwrap();
        let size_str = &decrypted_string[decrypted_string.len() - 12..];
        let size: u64 = size_str.parse().unwrap();

        println!("File: {}, Size: {}", filename, size);
        
        offset += 32;

        let data = read_file(&file, offset, size.try_into().unwrap())?;
        let decrypted_data = decrypt(&data, &key, &iv)?;

        if decrypted_data.starts_with(&[0x11, 0x22, 0x33, 0x44]) && filename != "SDIT.FDI"{ // header of obfuscated file, SDIT.FDI also has this header but seems to work differently so its skipped
            if verbose {
                println!("Obfuscated file header:");
                println!("- ID: {}", decrypted_data[5]);
                if 8 <= decrypted_data[5] && decrypted_data[5] <= 20 {
                    println!("-- Year guess: {}", decrypted_data[5] as u32 + 2003);
                }
                println!("- Base version?: {:02x?}", &decrypted_data[16..20]);
                println!("- Old version: {:02x?}", &decrypted_data[20..24]);
                println!("- Version: {:02x?}", &decrypted_data[24..28]);
                println!("1. Block index: {}", u16::from_be_bytes([decrypted_data[32], decrypted_data[33]]));
                println!("2. Control bytes: {:02x?}", &decrypted_data[34..36]);
                println!("3. Compressed size: {}", u32::from_be_bytes([decrypted_data[36], decrypted_data[37], decrypted_data[38], decrypted_data[39]]));
                println!("4. Uncompressed size: {}", u32::from_be_bytes([decrypted_data[40], decrypted_data[41], decrypted_data[42], decrypted_data[43]]));
                println!("5. Checksum: {:02x?}", &decrypted_data[44..48]);
            }

            println!("- Version: {}.{}{}{}", decrypted_data[24], decrypted_data[25], decrypted_data[26], decrypted_data[27]);
            println!("- Deciphering...");
            let deciphered_data = decipher(&decrypted_data[48..], decrypted_data[48..].len());

            let control_byte = decrypted_data[34];
            let out_data: Vec<u8>; 
            if verbose{println!("Control byte: {}", control_byte);};
            if control_byte == 3 {
                println!("-- Decompressing...");
                out_data = decompress_zlib(&deciphered_data)?;
            } else {
                println!("-- Uncompressed...");
                out_data = deciphered_data;
            }

            let first_byte;
            if out_data[1] & 0xF0 == 0xD0 {
                if verbose{println!("pre2013 detected!");};
                first_byte = out_data[1] & 0x0F;
            } else {
                if verbose{println!("2014+ detected!");};
                first_byte = out_data[1];
            }

            if verbose{println!("Content header:")};

            let dest_offset = u32::from_be_bytes([first_byte, out_data[2], out_data[3], out_data[4]]);
            if verbose{println!("1. Dest offset: {}", dest_offset);};

            let source_offset = u32::from_be_bytes([0x00, out_data[6], out_data[7], out_data[8]]);
            if verbose{println!("2. Source offset: {}", source_offset);};

            if verbose{println!("3. Size: {}", u32::from_be_bytes([out_data[9], out_data[10], out_data[11], out_data[12]]));};

            let path: PathBuf; 
            let msg: String;

            let source_name = filename.split(".").next().unwrap();

            if source_offset == 270 {   //unique for 2014-2018 files
                if verbose{println!("2014-2018 detected!")}
                let embedded_file_name_string = String::from_utf8_lossy(&out_data[14..270]);
                let embedded_file_name = embedded_file_name_string.split("\0").next().unwrap();
                println!("--- Embedded file: {}", embedded_file_name);
    
                let folder_path = Path::new(&output_path).join(source_name);
                fs::create_dir_all(&folder_path)?;
                path = Path::new(&folder_path).join(embedded_file_name);
                msg = format!("to {}", source_name);
            } else {
                path = Path::new(&output_path).join(format!("{}.bin", source_name));
                msg = format!("to {}.bin", source_name);
            }            

            fs::create_dir_all(&output_path)?;
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?;
    
            file.seek(SeekFrom::Start(dest_offset as u64))?;
            file.write_all(&out_data[source_offset as usize..])?;
            println!("--- Saved {}!", msg);

        } else {
            let out_data = decrypted_data;
            if filename.ends_with(".TXT") && !keep_txt {
                println!("{}", String::from_utf8_lossy(&out_data));
            } else {
                let path = Path::new(&output_path).join(filename);

                fs::create_dir_all(&output_path)?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .open(path)?;
  
                file.write_all(&out_data)?;
                println!("-- Saved file!");
            } 
        }

        println!();
        offset += size;
    }

    println!("Done! Extracted files saved to {}", output_path);

    Ok(())
}