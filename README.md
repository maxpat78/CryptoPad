CryptoPad
=========

A simple Notepad coded in Python and Tkinter (x86) and tested under Windows 8.1. It runs with both Python 2.7 and 3.4.


It is able to read and write ETXT text documents, which are simple ZIP archives encrypted with AES, for maximum security and portability.

It encrypts always with AES-256, but can decrypt also with 128 or 192 bit keys.

File contents are also deflated before encryption.


The well known AE-1 specification from WinZip[1] is implemented, so one of the following cryptographic toolkits/libraries is required to run the app:

- Python Cryptography Toolkit pycrypto[2]
- libeay32 from OpenSSL[3]
- Botan[4]
- NSS from Mozilla[5]

_libeay.c provides a C version of AES-256 CTR Little-Endian encryption performed by AE-1, openssl based.



[1] See http://www.winzip.com/aes_info.htm

[2] See https://www.dlitz.net/software/pycrypto/

[3] See https://www.openssl.org/

[4] See http://botan.randombit.net/

[5] See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS

