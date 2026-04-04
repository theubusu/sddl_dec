# sddl_dec
Tool for decrypting Panasonic TV SDDL.SEC files.   
This tool will decrypt and unpack the files from an SDDL.SEC firmware update package used on Panasonic TVs.  
**Notice:** The tool will not directly extract the contents of the firmware by itself! It only unpacks and decrypts the SDDL.SEC file. To inspect the output of the program, use a tool like [binwalk](github.com/ReFirmLabs/binwalk). To see what you can expect, read more below.
## Support
The tool should be able to extract all SDDL.SEC files.   
## Installation
You can download the latest auto build for Windows and Linux x86-64 from [here](https://nightly.link/theubusu/sddl_dec/workflows/rust/main/sddl_dec).  
Or, build from source, by downloading the code and running `cargo build --release`. The binary will be saved in `target/release`.  

If you prefer to use the old python version, you can find it in the `python` branch (Please note that it is now very outdated, and no support will be provided).
## Usage
`sddl_dec [OPTIONS] <INPUT_FILE> [OUTPUT_FOLDER]`  
`<INPUT_FILE>` - The file to extract.  
`<OUTPUT_FOLDER>` - Folder to save extracted files to. If not provided, will use `_<filename>`  
`[OPTIONS]` - Can be:  
`-v` - Verbose mode - Print more detailed information about the file    
`-s` - Save .TXT and TDI files (read more below)  
`-d` - Extract an SDBOOT-type file   
`-p` - Split an old PEAKS file   
`-a` - (for `-p`) PEAKS args offset  
`-h` - Show help message.  
## About SDDL.SEC and the output of the program
An SDDL.SEC file is an encrypted, ciphered and partially compressed archive that contains the firmware data for the TV.
The main contents of the file can consist of:
- SDIT.FDI - Probably stands for some combination of "Software Download Information Table" - it contains information about the modules contained within the file, their versions and respective models. It is not saved by default, but you can keep it with the `-s` option.
- A bunch of XXX.TXT files, each one respective to one group in the SDIT. They usually contain information about the target of the update. By default, they are not saved and will be only printed to output, but with the `-s` option they will be saved.
- `PEAKS` module - this is the main firmware data split into chunks, usually of 2/4MB of size - it is saved into a PEAKS.bin file, or in case of 2014-2018 files, the files embedded inside will be saved into a PEAKS folder.
The content of the `PEAKS` module varies depending on the TV's platform, from my findings the structure is:
    - For pre-2011 models, the structure should be the same as the 2011-2013 models, but the start of the data (magic "D50 ") will probably not be located at the beginning of the file, you *should* be able to use the below method if you trim it though. Sometimes the boot args (starting with "root=/dev/fmaX") can also be located further in the file, to correct it you can use the `-a` flag with the desired offset.  
    - For FreeBSD-based 2011-2013 models, and some later lower-end models: The output will be a PEAKS.bin blob that should start with the magic "D50 ". It can be split into partitions using the built-in `-p` flag. The resulting partitions will usually be of UFS format, which you can extract with [ufs-dump](https://github.com/theubusu/ufs-dump).
    - For FreeBSD/linux-based 2014-~2018? models - the output are 2 files in a PEAKS folder: "root.tgz" containing the rootfs filesystem, and a "DLDATA_LIST.TXT" file which specifies the partition it should be installed to.
    - For Linux-based 2019+ models - the output blob contains a bootloader, DTB and rootfs squashfs filesystem (binwalk)
- There can also be additional modules, such as `BOOT`, `PEAKSBT`, `STM`, `DTB` - these are either the TV's bootloader or some other firmware.
# License
Licensed under GNU GPL v3.  