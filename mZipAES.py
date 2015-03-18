# A micro reader & writer for AES-256 encrypted ZIP archives
# Based on Python 2.7 and pycrypto
import zlib, struct, time

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto import Random, Util
except:
    print "missing required package: pycrypto 2.6"

#~ Local file header:

    #~ local file header signature     4 bytes  (0x04034b50)
    #~ version needed to extract       2 bytes
    #~ general purpose bit flag        2 bytes
    #~ compression method              2 bytes
    #~ last mod file time              2 bytes
    #~ last mod file date              2 bytes
    #~ crc-32                          4 bytes
    #~ compressed size                 4 bytes
    #~ uncompressed size               4 bytes
    #~ filename length                 2 bytes
    #~ extra field length              2 bytes

    #~ filename (variable size)
    #~ extra field (variable size)

#~ Extended AES header (both local & central) based on WinZip 9 specs:

    #~ extra field header      2 bytes  (0x9901)
    #~ size                    2 bytes  (7)
    #~ version                 2 bytes  (1 or 2)
    #~ ZIP vendor              2 bytes  (actually, AE)
    #~ strength                1 byte   (AES 1=128-bit key, 2=192, 3=256)
    #~ actual compression      2 byte   (becomes 0x99 in LENT & CENT)

    #~ content data, as follows:
    #~ random salt (8, 12, 16 byte depending on key size)
    #~ 2-byte password verification value (from PBKDF2)
    #~ AES-CTR encrypted data
    #~ 10-byte HMAC-SHA1-80 authentication code for encrypted data

#~ NOTE: AE-1 preserves CRC-32 on uncompressed data, AE-2 sets it to zero.

  #~ Central File header:

    #~ central file header signature   4 bytes  (0x02014b50)
    #~ version made by                 2 bytes
    #~ version needed to extract       2 bytes
    #~ general purpose bit flag        2 bytes
    #~ compression method              2 bytes
    #~ last mod file time              2 bytes
    #~ last mod file date              2 bytes
    #~ crc-32                          4 bytes
    #~ compressed size                 4 bytes
    #~ uncompressed size               4 bytes
    #~ filename length                 2 bytes
    #~ extra field length              2 bytes
    #~ file comment length             2 bytes
    #~ disk number start               2 bytes
    #~ internal file attributes        2 bytes
    #~ external file attributes        4 bytes
    #~ relative offset of local header 4 bytes

    #~ filename (variable size)
    #~ extra field (variable size)
    #~ file comment (variable size)

  #~ End of central dir record:

    #~ end of central dir signature    4 bytes  (0x06054b50)
    #~ number of this disk             2 bytes
    #~ number of the disk with the
    #~ start of the central directory  2 bytes
    #~ total number of entries in
    #~ the central dir on this disk    2 bytes
    #~ total number of entries in
    #~ the central dir                 2 bytes
    #~ size of the central directory   4 bytes
    #~ offset of start of central
    #~ directory with respect to
    #~ the starting disk number        4 bytes
    #~ zipfile comment length          2 bytes
    #~ zipfile comment (variable size)

        

class MiniZipAE1Writer():
    def __init__ (p, stream, password):
        # Stream di output sul file ZIP
        p.fp = stream
        # Avvia il compressore Deflate "raw" tramite zlib
        p.compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        # Genera un salt casuale a 128-bit (16 byte) per AES-256
        p.salt = Random.get_random_bytes(16)
        # Genera una chiave a 256-bit per AES, un'altra per HMAC-SHA1-80 e 2 byte di controllo
        blob = PBKDF2(password, p.salt, 66)
        # Avvia la cifra AES con chiave a 256-bit in modo CTR *LITTLE-ENDIAN*
        p.encryptor = AES.new(blob[:32], AES.MODE_CTR, counter=Util.Counter.new(128, little_endian=True))
        # Avvia HMAC-SHA1-80
        p.hmac = HMAC.new(blob[32:64], digestmod=SHA)
        # WORD di verifica password
        p.chkword = blob[64:]

    def append(p, entry, s):
        # Nome del file da aggiungere
        p.entry = entry
        # Calcola il CRC-32 sui dati originali
        p.crc32 = zlib.crc32(s) & 0xFFFFFFFF
        # Comprime, cifra e calcola l'hash sul cifrato
        cs = p.compressor.compress(s) + p.compressor.flush()
        # csize = dati + salt (16) + chkword (2) + HMAC (10)
        p.usize, p.csize = len(s), len(cs)+28
        p.blob = p.encryptor.encrypt(cs)
        p.hmac.update(p.blob)

    def write(p):
        p.fp.write(p.PK0304())
        p.fp.write(p.salt)
        p.fp.write(p.chkword)
        p.fp.write(p.blob)
        # HMAC-SHA1-80 usa solo 80 dei 160 bit generati per l'hash
        p.fp.write(p.hmac.digest()[:10])
        cdir = p.PK0102()
        cdirpos = p.fp.tell()
        p.fp.write(cdir)
        p.fp.write(p.PK0506(len(cdir), cdirpos))
        p.fp.flush()

    def close(p):
        p.fp.close()

    def rewind(p):
        p.fp.seek(0, 0)
        
    def PK0304(p):
        dt = time.localtime()
        p.dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        p.dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
        return 'PK\x03\x04' + struct.pack('<5H3I2H', 0x33, 1, 99, p.dostime, p.dosdate, p.crc32, p.csize, p.usize, len(p.entry), 11) + p.entry + p.AEH()

    def AEH(p, method=8, version=1):
        # version=2 (AE-2) non registra il CRC-32, AE-1 lo fa
        # method=0 (non compresso), method=8 (deflated)
        return struct.pack('<4HBH', 0x9901, 7, version, 0x4541, 3, method)

    def PK0102(p):
        return 'PK\x01\x02' + struct.pack('<6H3I5H2I', 0x33, 0x33, 1, 99, p.dostime, p.dosdate, p.crc32, p.csize, p.usize, len(p.entry), 11, 0, 0, 0, 0x20, 0) + p.entry + p.AEH()

    def PK0506(p, cdirsize, offs):
        if hasattr(p, 'zipcomment'):
            return 'PK\x05\x06' + struct.pack('<4H2IH', 0, 0, 1, 1, cdirsize, offs, len(p.zipcomment)) + p.zipcomment
        else:
            return 'PK\x05\x06' + struct.pack('<4H2IH', 0, 0, 1, 1, cdirsize, offs, 0)


class MiniZipAE1Reader():
    def __init__ (p, stream, password):
        # Stream di input sul file ZIP
        p.fp = stream
        # Avvia il decompressore Deflate via zlib
        p.decompressor = zlib.decompressobj(-15)
        p.parse()
        # Rigenera una chiave a 256-bit per AES, un'altra per HMAC-SHA1-80 e 2 byte di controllo
        blob = PBKDF2(password, p.salt, 66)
        if p.chkword != blob[64:]:
            raise Exception("BAD PASSWORD")
        p.decryptor = AES.new(blob[:32], AES.MODE_CTR, counter=Util.Counter.new(128, little_endian=True))
        p.hmac = HMAC.new(blob[32:64], digestmod=SHA)
        p.hmac.update(p.blob)
        if p.hmac.digest()[:10] != p.digest:
            raise Exception("BAD HMAC-SHA1-80")
        cs = p.decryptor.decrypt(p.blob)
        p.s = p.decompressor.decompress(cs)
        crc32 = zlib.crc32(p.s) & 0xFFFFFFFF
        if crc32 != p.crc32:
            raise Exception("BAD CRC-32")
            
    def get(p):
        return p.s
        
    def close(p):
        p.fp.close()

    def rewind(p):
        p.fp.seek(0, 0)
        
    def parse(p):
        p.rewind()
        if p.fp.read(4) != 'PK\x03\x04':
            raise Exception("BAD LOCAL HEADER")
        ver1, flag, method, dtime, ddate, crc32, csize, usize, namelen, xhlen = struct.unpack('<5H3I2H', p.fp.read(26))
        #~ print ver1, flag, method, hex(dtime), hex(ddate), hex(crc32), csize, usize, namelen, xhlen
        if method != 99:
            raise Exception("NOT AES ENCRYPTED")
        if xhlen != 11:
            raise Exception("TOO MANY EXT HEADERS")
        p.entry = p.fp.read(namelen)
        xh, cb, ver, vendor, keybits, method = struct.unpack('<4HBH', p.fp.read(xhlen))
        if xh != 0x9901 or ver != 1 or keybits != 3 or vendor != 0x4541:
            raise Exception("UNKNOWN AE PROTOCOL")
        p.salt = p.fp.read(16)
        p.chkword = p.fp.read(2)
        p.blob = p.fp.read(csize-28)
        p.digest = p.fp.read(10)
        p.usize = usize
        p.crc32 = crc32
        


if __name__ == '__main__':
    zip = MiniZipAE1Writer(file('a.zip','wb'), 'password')
    zip.append('a.txt', 'CIAO')
    zip.write()
    zip.close()

    zip = MiniZipAE1Reader(file('a.zip','rb'), 'password')
    assert 'CIAO' == zip.get()
