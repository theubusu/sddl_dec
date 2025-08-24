# sddl_dec
Tool for decrypting Panasonic TV SDDL.SEC files. New version 4.0 rewritten in Rust for up to 25x the speed!  
This tool will decrypt and unpack the files from an SDDL.SEC firmware update package used on Panasonic TVs.  
**Notice:** The tool will not directly extract the contents of the firmware by itself! It only unpacks and decrypts the SDDL.SEC file. To inspect the output of the program, use a tool like [binwalk](github.com/ReFirmLabs/binwalk). To see what you can expect, read more below.
## Support
The tool will extract SDDL.SEC files from TVs released in and after 2011. Older files seem to use a different format.
## Installation
You can either:  
Download one of the prebuilt binaries from the Releases tab,  
or build from source, by downloading the code and running `cargo build --release`. The binary will be saved in `target/release`.  
  
If you prefer to use the old python version, you can find it in the `python` branch.
## Usage
`sddl_dec [OPTIONS] <INPUT_FILE> <OUTPUT_FOLDER>`  
`<INPUT_FILE>` - The SDDL.SEC file to extract.  
`<OUTPUT_FOLDER>` - Folder to save extracted files to.  
`[OPTIONS]` - Can be:  
`-v` - Verbose mode - print detailed information about extraction process.  
`-k` - Keep TXT files. (read more below)  
`-h` - Show help message.  
## About SDDL.SEC and the output of the program
An SDDL.SEC file is an encrypted, ciphered and partially compressed archive that contains the firmware data for the TV.
The main contents of the file can consist of:
- SDIT.FDI - looks like it stores some kind of configuration data for different models, format is currently unknown.
- A bunch of XXX.TXT files which contain the target and version of the update (These are skipped by default and printed to output instead because sometimes theres over 40 of them for some reason and they are not important. You can prevent that with the `-k` option.)
- PEAKS.FXX Files - these are the main firmware data split into chunks, usually of 2/4MB of size - they are saved into a PEAKS.bin file, or in case of 2014-2018 files, the files embedded inside will be saved into a PEAKS folder.
The output of the PEAKS files varies depending on the TV's platform, from my findings the structure is:
    - For 2011-2013 models, and some later "dumb" models, the output blob contains the FreeBSD kernel, UFS rootfs filesystem and a UFS filesystem (/usr) compressed by unknown method (This format is complicated and not yet fully known)
    - For 2014-~2018? models - the output are 2 files in a PEAKS folder: "root.tgz" containing the rootfs filesystem, and a "DLDATA_LIST.TXT" file which specifies the partition it should be installed to.
    - For 2019+ models - the output blob contains a bootloader, DTB and rootfs squashfs filesystem (binwalk)
- PEAKSBT.F00 - bootloader
- BOOT.F00 - bootloader
- STM.F00 - some kind of firmware file, maybe micom firmware
