use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::collections::HashSet;

use binrw::{BinRead, BinReaderExt};
use crate::include::*;

//These keys seem to be the same for most models
const KEYS: [AesKeyEntry; 2] = [
    //from tbl_sdboot;0, Decrypted with AES
    AesKeyEntry {
        key: [0x2e, 0x2a, 0x33, 0x62, 0x33, 0xe5, 0x5a, 0xba, 0xf5, 0xff, 0xec, 0x54, 0xf8, 0xab, 0x71, 0x25 ],
        iv:  [0x2c, 0xa4, 0xb4, 0x7a, 0xff, 0xcb, 0x1a, 0xe8, 0xe1, 0xea, 0x2d, 0x9e, 0xf5, 0x12, 0x62, 0x9a]
    },

    //from tbl_sdboot;1, Decrypted with AES
    AesKeyEntry {
        key: [0x24, 0x5e, 0x8d, 0xe8, 0xf4, 0x99, 0xb0, 0xf9, 0x6e, 0xc1, 0x55, 0xb6, 0x08, 0xe2, 0x42, 0xf3],
        iv:  [0x3e, 0x8f, 0x29, 0xd4, 0xba, 0xe7, 0x76, 0xa5, 0x18, 0xa7, 0xb6, 0x3c, 0x42, 0xca, 0x1b, 0x43]
    }
];

#[derive(Debug, BinRead)]
pub struct SdbootSecHeader {
    num_files_str_bytes: [u8; 4],
    key_id_str_bytes: [u8; 4],
    _unused: [u8; 24],
}

impl SdbootSecHeader {
    pub const SIZE: usize = 0x20;

    pub fn num_files(&self) -> u32 {
        let string = string_from_bytes(&self.num_files_str_bytes);
        string.parse().unwrap()
    }
    pub fn key_id(&self) -> u16 {
        let string = string_from_bytes(&self.key_id_str_bytes);
        string.parse().unwrap()
    }
}

pub struct FileEntry {
    name: String,
    size: usize,
    offset: u64,
}

#[derive(Debug, BinRead)]
pub struct SdbootEntryHeader {
    file_name_bytes: [u8; 0x34],
    file_size_str_bytes: [u8; 0xc],
}
impl SdbootEntryHeader {
    pub const SIZE: usize = 0x40;

    pub fn name(&self) -> String {
        string_from_bytes(&self.file_name_bytes)
    }
    pub fn file_size(&self) -> usize {
        let string = string_from_bytes(&self.file_size_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(Debug, BinRead)]
pub struct EntrySubHeader {
    size_str_bytes: [u8; 0xc],
    _unused: [u8; 20],
}
impl EntrySubHeader {
    pub fn size(&self) -> usize {
        let string = string_from_bytes(&self.size_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(Debug, BinRead)]
pub struct InfoListHeader {
    part_count: u16,
    _unk1: u32,
    _unk2: u32,
    _unk3: u32,
    _unk4: u16,
}

#[derive(Debug, BinRead)]
pub struct InfoListEntry {
    _crc: u32,
    out_size: u32,
    _stored_size: u32,
    compressed_flag: u8,
    ciphered_flag: u8,
    _unused: u16,
}
impl InfoListEntry {
    pub fn is_compressed(&self) -> bool {
        self.compressed_flag == 0x01
    }
    pub fn is_ciphered(&self) -> bool {
        self.ciphered_flag == 0x01
    }
}

pub fn get_file(mut in_file: &File, search_file_name: &str, file_list: &Vec<FileEntry>, key: &KeyEntry) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file_idx = file_list.iter().position(|entry| entry.name == search_file_name)
        .ok_or_else(|| format!("Requested file {} was not found!", search_file_name))?;  
    let entry = &file_list[file_idx];
    
    in_file.seek(SeekFrom::Start(entry.offset))?;
    let enc_data = read_exact(&mut in_file, entry.size)?;
    let dec_data = KeyEntry::decrypt(key, &enc_data)?;
    let mut data_rdr = Cursor::new(dec_data);

    let sub_hdr: EntrySubHeader = data_rdr.read_be()?;
    let data = read_exact(&mut data_rdr, sub_hdr.size() as usize)?;
    
    Ok(data)
}

pub fn extract_sdboot(file_path: PathBuf, output_folder: &String) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut secfile_hdr_reader = Cursor::new(decipher(&read_exact(&mut file, SdbootSecHeader::SIZE)?));
    let secfile_header: SdbootSecHeader = secfile_hdr_reader.read_be()?;

    let key_id = secfile_header.key_id();
    if key_id != 0 && key_id != 1 {
        return Err(format!("Invalid sdboot key_id! got {} but must be 0 or 1", key_id).into());
    }
    let key: KeyEntry = KeyEntry::AES(KEYS[key_id as usize]);

    println!("File info -\nKey ID: {}\nFile count: {}", secfile_header.key_id(), secfile_header.num_files());

    //create file list
    let mut file_list: Vec<FileEntry> = Vec::new();  
    for _i in 0..secfile_header.num_files() {
        let mut entry_header_reader = Cursor::new(KeyEntry::decrypt(&key, &read_exact(&mut file, SdbootEntryHeader::SIZE)?)?);
        let entry_header: SdbootEntryHeader = entry_header_reader.read_be()?;

        let offset = file.stream_position()?;
        //println!("File: {} - Offset: {}, Size: {}", entry_header.name(), offset, entry_header.file_size());

        file_list.push( FileEntry { name: entry_header.name(), size: entry_header.file_size(), offset });
        file.seek(SeekFrom::Current(entry_header.file_size() as i64))?;
    }

    fs::create_dir_all(output_folder)?;
    let mut processed_image_files: HashSet<String> = HashSet::new(); //so processed image files are not extracted later

    //check for "IMGFILE.TXT" , if it exists, we will extract NAND/NOR images. (old route?)
    if let Ok(imgfile_data) = get_file(&file, "IMGFILE.TXT", &mut file_list, &key) {
        //example-  nand: nandall.img
        let imgfile_text = string_from_bytes(&imgfile_data);
        let mut s = imgfile_text.trim_end().split(": ");
        let target = s.next().unwrap();     //"nand"
        let target_filename = s.next().unwrap();    //"nandall.img"

        println!("\nSaving {} to {}...", target, target_filename);
        let output_path = Path::new(&output_folder).join(&target_filename);
        let mut out_file = OpenOptions::new().write(true).create(true).truncate(true).open(&output_path)?;

        //get info file
        let infofile_name = format!("{}.inf", target_filename.split(".").next().unwrap());  //"nandall.inf"
        let infofile = get_file(&file, &infofile_name, &file_list, &key)?;
        let mut infofile_reader = Cursor::new(infofile);
        let info_header: InfoListHeader = infofile_reader.read_le()?;
        for i in 0..info_header.part_count {
            let part_entry: InfoListEntry = infofile_reader.read_le()?;
            println!("- ({}/{}) Size: {}, Compressed?: {}", i+1, info_header.part_count, part_entry.out_size, part_entry.is_compressed());

            let part_file_name = format!("{}{:02x}", target_filename, i); //not sure what happens if it goes over 255
            let mut part_data = get_file(&file, &part_file_name, &file_list, &key)?;

            if part_entry.is_ciphered() {
                println!("-- Deciphering...");
                part_data = decipher(&part_data);
            }

            if part_entry.is_compressed() {
                println!("-- Decompressing...");
                part_data = decompress_zlib(&part_data)?;
            }

            out_file.write_all(&part_data)?;
            processed_image_files.insert(part_file_name);
        }

        println!("--- Saved file!");
    }

    //extract the rest of the files
    for entry in file_list.iter() {
        if processed_image_files.contains(&entry.name) {
            continue;
        }

        println!("\nFile: {} - Size: {}", entry.name, entry.size);

        let file_data = get_file(&file, &entry.name, &file_list, &key)?;
        let output_path = Path::new(&output_folder).join(&entry.name);
        let mut out_file = OpenOptions::new().read(true).write(true).create(true).open(output_path)?;
        out_file.write_all(&file_data)?;
        println!("- Saved file!");
    }

    Ok(())
}