CryptoPad
=========

A simple Notepad coded in Python and Tkinter (x86) and tested under Windows 10.
It runs with both Python 2.7 and 3.11.
GPL licensed.


It is able to read and write text documents (encoded in ASCII, UTF-8 or UTF-16 with any line ending) incapsulated into simple ZIP archives and encrypted with AES for maximum security and portability.

It encrypts always with AES-256 but can decrypt with 128 or 192-bit keys, too.

File contents are deflated before encryption.


The well known AE specification from WinZip[1] is implemented, so one of the following cryptographic toolkits/libraries is required to run the app:

- Python Cryptography Toolkit PyCryptodome[2]
- libcrypto from OpenSSL[3] or LibreSSL[6]
- Botan[4]
- NSS3 from Mozilla[5]
- Libgcrypt from GNU project[7]

_libeay.c, _libnss.c, _libgcrypt.c and _libbotan.c provide C versions (wrappers) of AES-256 CTR Little-Endian encryption performed by AE.
 


[1] See http://www.winzip.com/aes_info.htm

[2] See https://pycryptodome.readthedocs.io/en/latest/

[3] See https://www.openssl.org/

[4] See http://botan.randombit.net/

[5] See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS

[6] See https://www.libressl.org/

[7] See https://www.gnu.org/software/libgcrypt/
