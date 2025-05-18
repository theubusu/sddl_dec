# sddl_dec
Tool for decrypting Panasonic TV SDDL.SEC files.  
This python script will decrypt and extract the files and PEAKS data from most SDDL.SEC files of a Panasonic TV.  
Supported TVs are from years 2011-2020. (Since 2021 Panasonic stopped providing downloadable software update files, and files older than 2011 seem to use a different format.)

To use, download both the sddl_dec.py file, and the crypto_key file.
Usage:  sddl_dec.py <SDDL.SEC file>

- Dependencies: Crypto.Cipher

The output will vary depending on the year of model the file comes from.  
FirefoxOS models will output a file that contains the bootloader, device tree and a squashfs image of the root (binwalk)  
Most Smart 2014-2019? models will output the rootfs in tgz format.  
Models 2013 and older, and some "dumb" TV models will output a containing UFS filesystem, and FreeBSD kernel(yes thats what panasonic tvs used to run on.) It also contains other currently unknown data. 

Released new 2.0 version after studying the code - it is faster and does not use temp folders anymore, doesn't rely on hardcoded code,  directly deciphers and appends PEAKS data into a PEAKS.bin file. However this version is harder to use for investigating SDDL.SEC files. Feel free to use older version for that.

This script makes use of code by NeSE Team found at https://nese.team/posts/justctf/ .

