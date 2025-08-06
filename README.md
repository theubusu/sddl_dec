# sddl_dec
Tool for decrypting Panasonic TV SDDL.SEC files. New version 3.0  
This Python script will decrypt and unpack the files from an SDDL.SEC firmware update package used on Panasonic TVs.  
This script uses information about SDDL.SEC files found by NeSE Team for JustCTF 2022 and found [here](https://nese.team/posts/justctf) (search for SDDL.SEC). Thank you!  
**Notice:** This script will not directly extract the contents of the firmware by itself! It only unpacks and decrypts the SDDL.SEC file. To inspect the output of the file, use a tool like [binwalk](github.com/ReFirmLabs/binwalk). To see what you can expect, read more below.
## Support
The provided key file can extract *most* SDDL.SEC files from TVs released in and after 2011. Older files seem to use a different format. If you want to try your own key, you can find it in `/usr/local/customer_dl/crypto_key` on the TV.  
## Usage
Dependancies: `Crypto.Cipher`  
`sddl_dec.py [-h] [-l] [-v] [-nj] [-kt] input_file crypto_key_file [output_folder]`  
`input_file` - The SDDL.SEC file to extract.  
`crypto_key_file` - Crypto key to be used to decrypt the file.  
`output_folder` - Folder to save extracted files to. Default: "out"  
`-h` - Show help message.  
`-l` - List contents of the file without extracting them.  
`-v` - Verbose mode - print detailed information about extraction process.  
`-nj` - Don't join PEAKS files. (read more below)  
`-kt` - Keep TXT files. (read more below)  
## About SDDL.SEC and the output of the program
An SDDL.SEC file is an encrypted, ciphered and partially compressed archive that contains the firmware data for the TV.
It has a 32 byte header, that mostly remains the same between files, but its structure is unknown, and a 128 or 256(in later files) byte footer, which is most likely a signature.  
The main contents of the file can consist of:
- SDIT.FDI - looks like it stores some kind of configuration data for different models, format is currently unknown.
- A bunch of XXX.TXT files which contain the target and version of the update (These are skipped by default and printed to output instead because somtimes theres over 40 of them for some reason and they are not important. You can prevent that with the `-kt` option.)
- PEAKS.FXX Files - these are the main firmware data split into chunks, usually of 2/4MB of size - they are combined into one PEAKS.bin file by default, you can prevent this by using `-nj` option.
The output of the PEAKS files varies depending on the TV's platform, from my findings the structure is:
    - For 2011-2013 models, and some later "dumb" models, the output contains the FreeBSD kernel, UFS rootfs filesystem and a UFS filesystem (/usr) compressed by unknown method (This format is complicated and not yet fully known)
    - For 2014-~2018? models - the output is a tgz archive containing the rootfs filesystem
    - For 2019+ models - the output contains a bootloader, DTB and rootfs squashfs filesystem (binwalk)
- PEAKSBT.FXX - bootloader
- BOOT.FXX - bootloader
- STM.FXX - some kind of firmware file, unknown
