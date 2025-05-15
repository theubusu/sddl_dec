# sddl_dec
Tool for decrypting Panasonic TV SDDL.SEC files.  
This python script will decrypt and extract the main data from most SDDL.SEC files of a Panasonic TV.  
Supported TVs are from years 2011-2020. (Since 2021 Panasonic stopped providing downloadable software update files, and files older than 2011 seem to use a different format.)

To use, download both the sddl_dec.py file, and the crypto_key file.
Usage:  sddl_dec.py <SDDL.SEC file> (-n)

- Adding -n at the end of the command will not delete the temp folder.
- Dependencies: Crypto.Cipher os sys struct zlib shutil tqdm tarfile

The output will vary depending on the year of model the file comes from.  
FirefoxOS models will output a file that contains the bootloader, device tree and a squashfs image of the root (binwalk)  
Most Smart 2014-2019? models will output the rootfs in tgz format.  
Models 2013 and older, and some "dumb" TV models will output a file of unknown format. Running it through binwalk shows many files present in there. My suspection is that it contains a UFS filesystem, which is what older Panasonic TVs used (yeah, they ran FreeBSD).

This is more a proof of concept than anything. More research on SDDL files needs to be done. I tried it on a bunch of SDDL files and got ok results, so I decided to upload it.

This script makes use of code by NeSE Team found at https://nese.team/posts/justctf/ .

