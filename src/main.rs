mod include;
use std::path::{Path, PathBuf};
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write, Cursor};
use clap::Parser;
use binrw::{BinReaderExt};
use crate::include::{read_exact, decrypt, decipher, decompress_zlib, SddlSecHeader, EntryHeader, ModuleHeader, ContentHeader};

/// Tool for decrypting and unpacking Panasonic TV SDDL.SEC update files. 
#[derive(Parser, Debug)]
struct Args {
    /// Show debug information about extraction process.
    #[arg(short = 'd')]
    debug: bool,

    /// Keep .TXT files
    #[arg(short = 'k')]
    keep_txt: bool,

    input_file: String,
    output_folder: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("sddl_dec Tool Version 5.0");
    let args = Args::parse();

    let file_path = args.input_file;
    println!("Input file: {}", file_path);

    let output_folder = args.output_folder;
    println!("Output folder: {}\n", output_folder);

    let debug = args.debug;
    let keep_txt = args.keep_txt;

    let mut file = File::open(file_path)?;

    let mut hdr_reader = Cursor::new(decipher(&read_exact(&mut file, 32)?));
    let hdr: SddlSecHeader = hdr_reader.read_be()?;
    if debug {println!("{:?}", hdr)};

    if !hdr.is_magic_valid() {
        println!("This is not a valid SDDL.SEC file, aborting!");
        return Ok(())
    } else {
        println!("Valid SDDL.SEC detected");
    }

    //SDIT.FDI + info files + module files
    let total_entry_count = 1 + hdr.info_entry_count() + hdr.module_entries_count();
    println!("File info:\nInfo entry count: {}\nModule entry count: {}\nTotal entry count: {}",
            hdr.info_entry_count(), hdr.module_entries_count(), total_entry_count);

    for i in 0..total_entry_count {
        let mut entry_header_reader = Cursor::new(decrypt(&read_exact(&mut file, 32)?)?);
        let entry_header: EntryHeader = entry_header_reader.read_be()?;
        if debug {println!("{:?}", entry_header)};

        println!("\n({}/{}) File: {}, Size: {}", i + 1, total_entry_count, entry_header.name(), entry_header.size());

        let data = read_exact(&mut file, entry_header.size() as usize)?;
        let dec_data = decrypt(&data)?;

        fs::create_dir_all(&output_folder)?;
        //detect the file type based on the counts of each file
        if i == 0 { //SDIT.FDI file
            if debug {println!("SDIT.FDI file")};
            let output_path = Path::new(&output_folder).join(entry_header.name());
            let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
            out_file.write_all(&dec_data)?;
            println!("-- Saved file!");

        } else if i - 1 < hdr.info_entry_count() { //.TXT info file
            if debug {println!(".TXT info file")};
            if !keep_txt {
                println!("{}", String::from_utf8_lossy(&dec_data));
                continue
            } else {
                let output_path = Path::new(&output_folder).join(entry_header.name());
                let mut out_file = OpenOptions::new().write(true).create(true).open(output_path)?;
                out_file.write_all(&dec_data)?;
                println!("-- Saved file!");
            }

        } else { //Module file
            if debug {println!("Module file")};
            let name = entry_header.name();
            let source_name = name.split(".").next().unwrap();
            if debug{println!("Source name: {}", source_name)};

            let mut module_reader = Cursor::new(dec_data);
            let module_header: ModuleHeader = module_reader.read_be()?;
            if debug {println!("{:?}", module_header)};
            println!("- Version: {}.{}{}{}", module_header.file_version[0], module_header.file_version[1], module_header.file_version[2], module_header.file_version[3]);

            let module_data = read_exact(&mut module_reader, module_header.compressed_data_size as usize)?;
            println!("- Deciphering...");
            let deciphered_data = decipher(&module_data);

            let content: Vec<u8>;
            if module_header.is_compressed() {
                println!("-- Decompressing...");
                content = decompress_zlib(&deciphered_data)?;
            } else {
                println!("-- Uncompressed...");
                content = deciphered_data;
            }

            let mut content_reader = Cursor::new(content);
            let content_header: ContentHeader = content_reader.read_be()?;
            if debug {println!("{:?}\nDest offset: {}\nSource offset: {}", content_header, content_header.dest_offset(), content_header.source_offset())};

            let output_path: PathBuf; 
            if content_header.source_offset() == 270 {
                if debug{println!("2014-2018 detected!")}
                let file_name_bytes = read_exact(&mut content_reader, 256)?;
                let file_name = include::string_from_bytes(&file_name_bytes);
                println!("--- File name: {}", file_name);

                let out_folder_path = Path::new(&output_folder).join(source_name);
                fs::create_dir_all(&out_folder_path)?;
                output_path = Path::new(&out_folder_path).join(file_name);
            } else {
                output_path = Path::new(&output_folder).join(format!("{}.bin", source_name));
            }

            let data = read_exact(&mut content_reader, content_header.size as usize)?;

            let mut out_file = OpenOptions::new().read(true).write(true).create(true).open(output_path)?;
            out_file.seek(SeekFrom::Start(content_header.dest_offset() as u64))?;
            out_file.write_all(&data)?;
            println!("--- Saved!");

        }
    }

    println!("\nDone! Saved extracted files to {}", output_folder);

    Ok(())
}