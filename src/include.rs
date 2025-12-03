use std::io::{self, Read};

use binrw::{BinRead};
use aes::Aes128;
use flate2::read::ZlibDecoder;
use cbc::{Decryptor, cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit}};
type Aes128CbcDec = Decryptor<Aes128>;

pub fn string_from_bytes(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).to_string()
}

#[derive(Debug, BinRead)]
pub struct SddlSecHeader {
    #[br(count = 4)] magic_bytes: Vec<u8>, //0x11, 0x22, 0x33, 0x44
    #[br(count = 4)] _unused: Vec<u8>,
    #[br(count = 4)] info_entries_count_str_bytes: Vec<u8>,
    #[br(count = 4)] module_entries_count_str_bytes: Vec<u8>,
    #[br(count = 16)] _unk: Vec<u8>,
}
impl SddlSecHeader {
    pub fn is_magic_valid(&self) -> bool {
        self.magic_bytes == b"\x11\x22\x33\x44"
    }
    pub fn info_entry_count(&self) -> u32 {
        let string = string_from_bytes(&self.info_entries_count_str_bytes);
        string.parse().unwrap()
    }
    pub fn module_entries_count(&self) -> u32 {
        let string = string_from_bytes(&self.module_entries_count_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(Debug, BinRead)]
pub struct EntryHeader {
    #[br(count = 12)] name_str_bytes: Vec<u8>,
    #[br(count = 12)] size_str_bytes: Vec<u8>,
}
impl EntryHeader {
    pub fn name(&self) -> String {
        string_from_bytes(&self.name_str_bytes)
    }
    pub fn size(&self) -> u64 {
        let string = string_from_bytes(&self.size_str_bytes);
        string.parse().unwrap()
    }
}

#[derive(Debug, BinRead)]
pub struct ModuleHeader {
    #[br(count = 4)] _magic_bytes: Vec<u8>, //0x11, 0x22, 0x33, 0x44
    _unk1: u8,
    _id: u8,
    #[br(count = 10)] _unused: Vec<u8>,
    #[br(count = 4)] _file_base_version: Vec<u8>,
    #[br(count = 4)] _file_previous_version: Vec<u8>,
    #[br(count = 4)] pub file_version: Vec<u8>,
    #[br(count = 4)] _unused2: Vec<u8>,
    _index: u16,
    #[br(count = 2)] control_bytes: Vec<u8>,
    pub compressed_data_size: u32,
    _uncompressed_data_size: u32,
    _checksum: u32,
}
impl ModuleHeader {
    pub fn is_compressed(&self) -> bool {
        self.control_bytes[0] == 0x3
    }
}

#[derive(Debug, BinRead)]
pub struct ContentHeader {
    _magic1: u8,
    #[br(count = 4)] dest_offset_bytes: Vec<u8>,
    #[br(count = 4)] source_offset_bytes: Vec<u8>,
    pub size: u32,
    _magic2: u8,
}
impl ContentHeader {
    pub fn dest_offset(&self) -> u32 {
        let first_byte;
        if self.dest_offset_bytes[0] & 0xF0 == 0xD0 {
            first_byte = self.dest_offset_bytes[0] & 0x0F;
        } else {
            first_byte = self.dest_offset_bytes[0];
        }
        u32::from_be_bytes([first_byte, self.dest_offset_bytes[1], self.dest_offset_bytes[2], self.dest_offset_bytes[3]])
    }
    pub fn source_offset(&self) -> u32 {
        u32::from_be_bytes([0x00, self.source_offset_bytes[1], self.source_offset_bytes[2], self.source_offset_bytes[3]])
    }
}

pub fn read_exact<R: Read>(reader: &mut R, size: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

static DEC_KEY: [u8; 16] = [
    0x26, 0xE0, 0x96, 0xD3, 0xEF, 0x8A, 0x8F, 0xBB,
    0xAA, 0x5E, 0x51, 0x6F, 0x77, 0x26, 0xC2, 0x2C,
];
    
static DEC_IV: [u8; 16] = [
    0x3E, 0x4A, 0xE2, 0x3A, 0x69, 0xDB, 0x81, 0x54,
    0xCD, 0x88, 0x38, 0xC4, 0xB9, 0x0C, 0x76, 0x66,
];

pub fn decrypt(encrypted_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = encrypted_data.to_vec();
    let decryptor = Aes128CbcDec::new((&DEC_KEY).into(), (&DEC_IV).into());
    let decrypted = decryptor.decrypt_padded_mut::<Pkcs7>(&mut data)
        .map_err(|e| format!("!!Decryption error!!: {:?}", e))?;
    
    Ok(decrypted.to_vec())
}

//ported from original from https://nese.team/posts/justctf/
pub fn decipher(s: &[u8]) -> Vec<u8> {
    let len_ = s.len();
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

pub fn decompress_zlib(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;

    Ok(decompressed)
}