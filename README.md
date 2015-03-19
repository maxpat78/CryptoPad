CryptoPad
=========

A simple Notepad coded in Python 2.7 and tested under Windows 8.1.


It is able to read and write ETXT text documents, which are simple ZIP archives encrypted with AES-256, for maximum portability.
File contents are also deflated before encryption.


The well known AE-1 specification[1] is implemented, so installing the additional Python Cryptography Toolkit pycrypto[2] is required to run the app.



[1] See http://www.winzip.com/aes_info.htm

[2] See https://www.dlitz.net/software/pycrypto/
