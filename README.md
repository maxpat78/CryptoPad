CryptoPad
=========

A simple Notepad coded in Python and Tkinter, tested under Windows 11 and Python 3.11 (x64), GPL licensed.

It is able to read and write text documents (encoded in ASCII, UTF-8 or UTF-16 with any line ending) incapsulated into simple ZIP archives and encrypted with AES-256 for maximum security and portability (it can decrypt old documents with 128 or 192-bit keys, too).

File contents are reversed and deflated before encryption: the format is the same found in my CryptoPad-Win32 project.

The well known AE-1 specification from WinZip[1] is implemented, so one of the following cryptographic toolkits/libraries is required to run the app:

- pycryptodome[2]
- libeay32/libcrypto from OpenSSL[3] or LibreSSL[6]
- Botan[4]
- NSS3 from Mozilla[5]
- Libgcrypt from GNU project[7]

_libeay.c, _libnss.c, _libgcrypt.c and _libbotan.c provide C versions (wrappers) of AES-256 CTR Little-Endian encryption performed by AE-1.



[1] See http://www.winzip.com/aes_info.htm

[2] See https://www.pycryptodome.org/

[3] See https://www.openssl.org/

[4] See http://botan.randombit.net/ (V2.x supported. Old V1.x code was dropped).

[5] See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS (at least nss3, freebl3, softokn3 and mozglue dlls, found in any Firefox installation, are required).

[6] See https://www.libressl.org/

[7] See https://www.gnu.org/software/libgcrypt/
