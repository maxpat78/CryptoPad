# A micro reader & writer for AES encrypted ZIP archives

# Encrypts in AES-256, decrypts with smaller keys, too

# Based on Python x86. It requires one of the cypto toolkits/libraries:
# pycrypto, libeay (libcrypto) from OpenSSL, botan or (lib)NSS3 from Mozilla

# TODO: use ctypes.util.find_library

from __future__ import print_function
import zlib, struct, time, sys
from ctypes import *

if sys.version_info < (3,0):
    range = xrange

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto import Random, Util
    PYCRYPTOAVAILABLE=1
except:
    PYCRYPTOAVAILABLE=0

class Crypto_PyCrypto:
    KitName = 'pycrypto 2.6+'
    
    def __init__(p):
        p.loaded = PYCRYPTOAVAILABLE

    def AE_gen_salt(p):
        "Genera 128 bit casuali di salt per AES-256"
        return Random.get_random_bytes(16)

    def AE_derive_keys(p, password, salt):
        "Con la password ZIP e il salt casuale, genera le chiavi per AES \
       e HMAC-SHA1-80, e i 16 bit di controllo"
        keylen = {8:16,12:24,16:32}[len(salt)]
        if sys.version_info >= (3,0) and type(password)!=type(b''):
            password = bytes(password, 'utf8')
        s = PBKDF2(password, salt, 2*keylen+2)
        return s[:keylen], s[keylen:2*keylen], s[2*keylen:]

    def AE_ctr_crypt(p, key, s):
        "Cifra/decifra in AES-256 CTR con contatore Little Endian"
        enc = AES.new(key, AES.MODE_CTR, counter=Util.Counter.new(128, little_endian=True))
        return enc.encrypt(s)

    def AE_hmac_sha1_80(p, key, s):
        "Autentica con HMAC-SHA1-80"
        hmac = HMAC.new(key, digestmod=SHA)
        hmac.update(s)
        return hmac.digest()[:10]



class Crypto_OpenSSL:
    KitName = 'OpenSSL 1.0.2+'
    
    def __init__(p):
        p.loaded = 0
        try:
            if sys.platform != 'win32':
                # ...or whatever/wherever
                p.handle = CDLL('libcrypto.so.1.0.0')
            else:
                p.handle = CDLL('libcrypto-1_1') or CDLL('libeay32')
            p.loaded = 1
        except:
            pass

        # Se presente, sostituisce con la versione C
        try:
            import _libeay
            p.AES_ctr128_le_crypt = _libeay.AES_ctr128_le_crypt
        except:
            pass

    # Nel modo CTR il cifrato risulta dallo XOR tra ciascun blocco di testo
    # in chiaro e un contatore cifrato in modo ECB realizzato,
    # preferibilmente, mediante unione di n bit casuali con n bit di contatore.
    # Il protocollo AE di WinZip richiede che il contatore sia un numero a
    # 128 bit codificato in Little Endian diversamente dalle maggiori
    # implementazioni in Big Endian; inoltre il contatore parte da 1 senza
    # alcun contenuto casuale.
    #
    # NOTA: la versione C è veloce quanto quella pycrypto; questa, ibrida,
    # circa 35 volte più lenta!
    #
    # !!!CAVE!!! Su Python 3.4 è circa 1,6x più lenta rispetto a Python 2.7!
    def AES_ctr128_le_crypt(self, key, s):
        if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")
        #~ # This slows down to 755 K/s
        #~ self.handle.AES_ecb_encrypt.argtypes = [c_char_p, c_char_p, c_void_p, c_int]        
        #~ self.handle.AES_ecb_encrypt.restype = [c_int]        
        AES_KEY = create_string_buffer(244)
        self.handle.AES_set_encrypt_key(key, len(key)*8, AES_KEY)
        
        buf = (c_byte*len(s)).from_buffer_copy(s)
        
        ctr = create_string_buffer(16)
        ectr = create_string_buffer(16)
        pectr = cast(ectr, POINTER(c_byte))
        cnt = 0
        j = 0
        fuAES = self.handle.AES_ecb_encrypt
        for i in range(len(s)):
            j=i%16
            if not j:
                cnt += 1
                struct.pack_into('<Q', ctr, 0, cnt)
                fuAES(ctr, ectr, AES_KEY, 1)
            buf[i] ^= pectr[j]
        if sys.version_info >= (3,0):
            return bytes(buf)
        else:
            return str(bytearray(buf))

    def AE_gen_salt(p):
        "Genera 128 bit casuali di salt per AES-256"
        key = create_string_buffer(16)
        p.handle.RAND_poll()
        if sys.platform == 'win32':
            p.handle.RAND_screen()
        if not p.handle.RAND_bytes(key, 16):
            p.handle.RAND_pseudo_bytes(key, 16)
        return key.raw

    def AE_derive_keys(p, password, salt):
        "Con la password ZIP e il salt casuale, genera le chiavi per AES \
        e HMAC-SHA1-80, e i 16 bit di controllo"
        keylen = {8:16,12:24,16:32}[len(salt)]
        if sys.version_info >= (3,0) and type(password)!=type(b''):
            password = bytes(password, 'utf8')
        s = create_string_buffer(2*keylen+2)
        p.handle.PKCS5_PBKDF2_HMAC_SHA1(password, len(password), salt, len(salt), 1000, 2*keylen+2, s)
        return s.raw[:keylen], s.raw[keylen:2*keylen], s.raw[2*keylen:]

    def AE_ctr_crypt(p, key, s):
        "Cifra/decifra in AES-256 CTR con contatore Little Endian"
        return p.AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(p, key, s):
        "Autentica con HMAC-SHA1-80"
        digest = p.handle.HMAC(p.handle.EVP_sha1(), key, len(key), s, len(s), 0, 0)
        return cast(digest, POINTER(c_char*10)).contents.raw




class Crypto_Botan:
    KitName = 'Botan 1.11.16+'
    
    def __init__(p):
        p.loaded = 0
        try:
            if sys.platform != 'win32':
                # ...or whatever/wherever
                p.handle = CDLL('libbotan-1.11.so')
            else:
                p.handle = CDLL('botan')
            p.loaded = 1
        except:
            pass

    def AES_ctr128_le_crypt(self, key, s):
        if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")

        cipher = c_void_p(0)
        mode = {16:b'AES-128/ECB', 24:b'AES-192/ECB', 32:b'AES-256/ECB'}[len(key)]
        self.handle.botan_cipher_init(byref(cipher), mode, 0)
        self.handle.botan_cipher_set_key(cipher, key, len(key))
        
        buf = (c_byte*len(s)).from_buffer_copy(s)
        ctr = create_string_buffer(16)
        ectr = create_string_buffer(16)
        pectr = cast(ectr, POINTER(c_byte))
        cnt = 0
        j = 0
        o0 = byref(c_size_t(0))
        i0 = byref(c_size_t(0))
        u = c_uint32(1)
        fuAES = self.handle.botan_cipher_update
        for i in range(len(s)):
            j=i%16
            if not j:
                cnt += 1
                struct.pack_into('<Q', ctr, 0, cnt)
                fuAES(cipher, u, ectr, 16, o0, ctr, 16, i0)
            buf[i] ^= pectr[j]
        if sys.version_info >= (3,0):
            return bytes(buf)
        else:
            return str(bytearray(buf))

    def AE_gen_salt(p):
        "Genera 128 bit casuali di salt per AES-256"
        key = create_string_buffer(16)
        rng = c_void_p(0)
        p.handle.botan_rng_init(byref(rng), b'system')
        p.handle.botan_rng_get(rng, key, c_size_t(16))
        return key.raw

    def AE_derive_keys(p, password, salt):
        "Con la password ZIP e il salt casuale, genera le chiavi per AES \
        e HMAC-SHA1-80, e i 16 bit di controllo"
        keylen = {8:16,12:24,16:32}[len(salt)]
        if sys.version_info >= (3,0) and type(password)!=type(b''):
            password = bytes(password, 'utf8')
        s = create_string_buffer(2*keylen+2)
        p.handle.botan_pbkdf(b'PBKDF2(SHA-1)', s, 2*keylen+2, password, salt, len(salt), 1000)
        return s.raw[:keylen], s.raw[keylen:2*keylen], s.raw[2*keylen:]

    def AE_ctr_crypt(p, key, s):
        "Cifra/decifra in AES-256 CTR con contatore Little Endian"
        return p.AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(p, key, s):
        "Autentica con HMAC-SHA1-80"
        digest = create_string_buffer(20)
        mac = c_void_p(0)
        p.handle.botan_mac_init(byref(mac), b'HMAC(SHA-1)', 0)
        p.handle.botan_mac_set_key(mac, key, len(key))
        p.handle.botan_mac_update(mac, s, len(s))
        p.handle.botan_mac_final(mac, digest)
        return cast(digest, POINTER(c_char*10)).contents.raw
    


class Crypto_NSS:
    KitName = 'Mozilla NSS3'
    
    # In lib\util\seccommon.h
    class SECItemStr(Structure):
        _fields_ = [('SECItemType', c_uint), ('data', POINTER(c_char)), ('len', c_uint)]

    def __init__(p):
        p.loaded = 0
        try:
            if sys.platform != 'win32':
                # ...or whatever/wherever
                p.handle = CDLL('libnss3.so')
            else:
                p.handle = CDLL('nss3')
            p.handle.NSS_NoDB_Init(".")
            # Servono almeno le DLL nss3, softokn3, freebl3, mozglue
            if not p.handle.NSS_IsInitialized():
                raise Exception("NSS3 INITIALIZATION FAILED")
            p.loaded = 1
        except:
            pass

        # Se presente, sostituisce con la versione C
        try:
            import _libnss
            p.AES_ctr128_le_crypt = _libnss.AES_ctr128_le_crypt
        except:
            pass

    def AES_ctr128_le_crypt(self, key, s):
        if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")
        
        # In nss\lib\util\pkcs11t.h:
        # CKM_AES_ECB = 0x1081
        slot = self.handle.PK11_GetBestSlot(0x1081, 0)
        
        ki = self.SECItemStr()
        ki.SECItemType = 0 # type siBuffer
        # Esiste un modo migliore? Purtroppo .data non può essere c_char_p
        # in quanto troncherebbe al primo NULL
        ki.data = (c_char*len(key)).from_buffer_copy(key)
        ki.len = len(key)
        
        # PK11_OriginUnwrap = 4
        # CKA_ENCRYPT = 0x104
        sk = self.handle.PK11_ImportSymKey(slot, 0x1081, 4, 0x104, byref(ki), 0)
        sp = self.handle.PK11_ParamFromIV(0x1081, 0)
        ctxt = self.handle.PK11_CreateContextBySymKey(0x1081, 0x104, sk, sp)
        
        buf = (c_byte*len(s)).from_buffer_copy(s)
        ctr = create_string_buffer(16)
        ectr = create_string_buffer(16)
        pectr = cast(ectr, POINTER(c_byte))
        olen = c_uint32(0)
        cnt = 0
        j = 0
        fuAES = self.handle.PK11_CipherOp
        for i in range(len(s)):
            j=i%16
            if not j:
                cnt += 1
                struct.pack_into('<Q', ctr, 0, cnt)
                fuAES(ctxt, ectr, byref(olen), 16, ctr, 16)
            buf[i] ^= pectr[j]
        self.handle.PK11_DestroyContext(ctxt, 1)
        self.handle.PK11_FreeSymKey(sk)
        self.handle.PK11_FreeSlot(slot)

        if sys.version_info >= (3,0):
            return bytes(buf)
        else:
            return str(bytearray(buf))

    def AE_gen_salt(p):
        "Genera 128 bit casuali di salt per AES-256"
        key = create_string_buffer(16)
        p.handle.PK11_GenerateRandom(key, 16)
        return key.raw

    def AE_derive_keys(p, password, salt):
        "Con la password ZIP e il salt casuale, genera le chiavi per AES \
      e HMAC-SHA1-80, e i 16 bit di controllo"
        keylen = {8:16,12:24,16:32}[len(salt)]
        if sys.version_info >= (3,0) and type(password)!=type(b''):
            password = bytes(password, 'utf8')
        
        si = p.SECItemStr()
        si.SECItemType = 0 # type siBuffer
        si.data = (c_char*len(salt)).from_buffer_copy(salt)
        si.len = len(salt)

        # SEC_OID_PKCS5_PBKDF2 = 291
        # SEC_OID_HMAC_SHA1 = 294
        algid = p.handle.PK11_CreatePBEV2AlgorithmID(291, 291, 294, 2*keylen+2, 1000, byref(si))

        # CKM_PKCS5_PBKD2 = 0x3B0
        slot = p.handle.PK11_GetBestSlot(0x3B0, 0)
        
        pi = p.SECItemStr()
        pi.SECItemType = 0 # type siBuffer
        pi.data = (c_char*len(password)).from_buffer_copy(password)
        pi.len = len(password)
        
        sk = p.handle.PK11_PBEKeyGen(slot, algid, byref(pi), 0, 0)
        p.handle.PK11_ExtractKeyValue(sk)
        pkd = p.handle.PK11_GetKeyData(sk)
        rawkey = cast(pkd, POINTER(p.SECItemStr)).contents.data[:2*keylen+2]
        a,b,c = rawkey[:keylen], rawkey[keylen:2*keylen], rawkey[2*keylen:] 
        p.handle.PK11_FreeSymKey(sk)
        p.handle.PK11_FreeSlot(slot)
        return a, b, c

    def AE_ctr_crypt(p, key, s):
        "Cifra/decifra in AES-256 CTR con contatore Little Endian"
        return p.AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(p, key, s):
        "Autentica con HMAC-SHA1-80"
        ki = p.SECItemStr()
        ki.SECItemType = 0 # type siBuffer
        ki.data = (c_char*len(key)).from_buffer_copy(key)
        ki.len = len(key)

        # In lib\util\pkcs11t.h
        # CKM_SHA_1_HMAC = 0x00000221
        # CKA_SIGN = 0x00000108
        slot = p.handle.PK11_GetBestSlot(0x221, 0)
        # PK11_OriginUnwrap = 4
        sk = p.handle.PK11_ImportSymKey(slot, 0x221, 4, 0x108, byref(ki), 0)

        np = p.SECItemStr()
        ctxt = p.handle.PK11_CreateContextBySymKey(0x221, 0x108, sk, byref(np))
        p.handle.PK11_DigestBegin(ctxt)
        p.handle.PK11_DigestOp(ctxt, s, len(s))
        digest = create_string_buffer(20)
        length = c_uint32(0)
        p.handle.PK11_DigestFinal(ctxt, digest, byref(length), 20)

        p.handle.PK11_DestroyContext(ctxt, 1)
        p.handle.PK11_FreeSymKey(sk)
        p.handle.PK11_FreeSlot(slot)

        return digest.raw[:10]



"""Local file header:

    local file header signature     4 bytes  (0x04034b50)
    version needed to extract       2 bytes
    general purpose bit flag        2 bytes
    compression method              2 bytes
    last mod file time              2 bytes
    last mod file date              2 bytes
    crc-32                          4 bytes
    compressed size                 4 bytes
    uncompressed size               4 bytes
    filename length                 2 bytes
    extra field length              2 bytes

    filename (variable size)
    extra field (variable size)

Extended AES header (both local & central) based on WinZip 9 specs:

    extra field header      2 bytes  (0x9901)
    size                    2 bytes  (7)
    version                 2 bytes  (1 or 2)
    ZIP vendor              2 bytes  (actually, AE)
    strength                1 byte   (AES 1=128-bit key, 2=192, 3=256)
    actual compression      2 byte   (becomes 0x99 in LENT & CENT)

    content data, as follows:
    random salt (8, 12, 16 byte depending on key size)
    2-byte password verification value (from PBKDF2)
    AES-CTR-LE encrypted data
    10-byte HMAC-SHA1-80 authentication code for encrypted data

NOTE: AE-1 preserves CRC-32 on uncompressed data, AE-2 sets it to zero.

  Central File header:

    central file header signature   4 bytes  (0x02014b50)
    version made by                 2 bytes
    version needed to extract       2 bytes
    general purpose bit flag        2 bytes
    compression method              2 bytes
    last mod file time              2 bytes
    last mod file date              2 bytes
    crc-32                          4 bytes
    compressed size                 4 bytes
    uncompressed size               4 bytes
    filename length                 2 bytes
    extra field length              2 bytes
    file comment length             2 bytes
    disk number start               2 bytes
    internal file attributes        2 bytes
    external file attributes        4 bytes
    relative offset of local header 4 bytes

    filename (variable size)
    extra field (variable size)
    file comment (variable size)

  End of central dir record:

    end of central dir signature    4 bytes  (0x06054b50)
    number of this disk             2 bytes
    number of the disk with the
    start of the central directory  2 bytes
    total number of entries in
    the central dir on this disk    2 bytes
    total number of entries in
    the central dir                 2 bytes
    size of the central directory   4 bytes
    offset of start of central
    directory with respect to
    the starting disk number        4 bytes
    zipfile comment length          2 bytes
    zipfile comment (variable size)"""



crypto_kit = None
for C in (Crypto_PyCrypto, Crypto_OpenSSL, Crypto_Botan, Crypto_NSS):
    try:
        crypto_kit = C()
        if crypto_kit.loaded:
            break
    except:
        continue
if crypto_kit == None:
    raise Exception("NO CRYPTO KIT FOUND - ABORTED!")



class MiniZipAE1Writer():
    def __init__ (p, stream, password):
        # Stream di output sul file ZIP
        p.fp = stream
        # Avvia il compressore Deflate "raw" tramite zlib
        p.compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        p.salt = crypto_kit.AE_gen_salt()
        p.aes_key, p.hmac_key, p.chkword = crypto_kit.AE_derive_keys(password, p.salt)
        
    def append(p, entry, s):
        # Nome del file da aggiungere
        if sys.version_info >= (3,0):
            p.entry = bytes(entry, 'utf8')
        else:
            p.entry = entry
        # Calcola il CRC-32 sui dati originali
        p.crc32 = zlib.crc32(s) & 0xFFFFFFFF
        # Comprime, cifra e calcola l'hash sul cifrato
        cs = p.compressor.compress(s) + p.compressor.flush()
        # csize = salt (16) + chkword (2) + len(s) + HMAC (10)
        p.usize, p.csize = len(s), len(cs)+28
        p.blob = crypto_kit.AE_ctr_crypt(p.aes_key, cs)

    def write(p):
        p.fp.write(p.PK0304())
        p.fp.write(p.salt)
        p.fp.write(p.chkword)
        p.fp.write(p.blob)
        p.fp.write(crypto_kit.AE_hmac_sha1_80(p.hmac_key, p.blob))
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
        return b'PK\x03\x04' + struct.pack('<5H3I2H', 0x33, 1, 99, p.dostime, p.dosdate, p.crc32, p.csize, p.usize, len(p.entry), 11) + p.entry + p.AEH()

    def AEH(p, method=8, version=1):
        # version=2 (AE-2) non registra il CRC-32, AE-1 lo fa
        # method=0 (non compresso), method=8 (deflated)
        return struct.pack('<4HBH', 0x9901, 7, version, 0x4541, 3, method)

    def PK0102(p):
        return b'PK\x01\x02' + struct.pack('<6H3I5H2I', 0x33, 0x33, 1, 99, p.dostime, p.dosdate, p.crc32, p.csize, p.usize, len(p.entry), 11, 0, 0, 0, 0x20, 0) + p.entry + p.AEH()

    def PK0506(p, cdirsize, offs):
        if hasattr(p, 'zipcomment'):
            if sys.version_info >= (3,0):
                p.zipcomment = bytes(p.zipcomment, 'utf8')
            return b'PK\x05\x06' + struct.pack('<4H2IH', 0, 0, 1, 1, cdirsize, offs, len(p.zipcomment)) + p.zipcomment
        else:
            return b'PK\x05\x06' + struct.pack('<4H2IH', 0, 0, 1, 1, cdirsize, offs, 0)


class MiniZipAE1Reader():
    def __init__ (p, stream, password):
        # Stream di input sul file ZIP
        p.fp = stream
        # Avvia il decompressore Deflate via zlib
        p.decompressor = zlib.decompressobj(-15)
        p.parse()
        aes_key, hmac_key, chkword = crypto_kit.AE_derive_keys(password, p.salt)
        if p.chkword != chkword:
            raise Exception("BAD PASSWORD")
        if p.digest != crypto_kit.AE_hmac_sha1_80(hmac_key, p.blob):
            raise Exception("BAD HMAC-SHA1-80")
        cs = crypto_kit.AE_ctr_crypt(aes_key, p.blob)
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
        if p.fp.read(4) != b'PK\x03\x04':
            raise Exception("BAD LOCAL HEADER")
        ver1, flag, method, dtime, ddate, crc32, csize, usize, namelen, xhlen = struct.unpack('<5H3I2H', p.fp.read(26))
        #~ print ver1, flag, method, hex(dtime), hex(ddate), hex(crc32), csize, usize, namelen, xhlen
        if method != 99:
            raise Exception("NOT AES ENCRYPTED")
        if xhlen != 11:
            raise Exception("TOO MANY EXT HEADERS")
        p.entry = p.fp.read(namelen)
        xh, cb, ver, vendor, keybits, method = struct.unpack('<4HBH', p.fp.read(xhlen))
        if xh != 0x9901 or ver != 1 or vendor != 0x4541:
            raise Exception("UNKNOWN AE PROTOCOL")
        if keybits == 3:
            p.salt = p.fp.read(16)
            DELTA=28
        elif keybits == 2:
            p.salt = p.fp.read(12)
            DELTA=24
        elif keybits == 1:
            p.salt = p.fp.read(8)
            DELTA=20
        else:
            raise Exception("UNKNOWN AES KEY STRENGTH")
        p.chkword = p.fp.read(2)
        p.blob = p.fp.read(csize-DELTA)
        p.digest = p.fp.read(10)
        p.usize = usize
        p.crc32 = crc32
        


if __name__ == '__main__':
    import io, timeit
    
    f = io.BytesIO()
    print('Testing MiniZipAE1Writer')
    zip = MiniZipAE1Writer(f, 'password')
    zip.append('a.txt', 2155*b'CIAO')
    zip.write()
    
    f.seek(0,0)

    print('Testing MiniZipAE1Reader')
    zip = MiniZipAE1Reader(f, 'password')
    assert 2155*b'CIAO' == zip.get()

    salt = b'\x01' + b'\x00'*15
    pw = b'password'

    for C in (Crypto_PyCrypto, Crypto_NSS, Crypto_OpenSSL, Crypto_Botan):
        try:
            o = C()
            if o.loaded:
                print('Testing ', o.KitName)
            else:
                print(o.KitName, ' not available.')
        except:
            continue
        
        print(' + random salt generation',)
        try:
            assert len(o.AE_gen_salt()) == 16
        except:
            print('   FAILED.')
        
        print(' + pbkdf2 key generation')
        try:
            assert o.AE_derive_keys(pw, salt)[-1] == b'\xE2\xE3'
        except:
            print('   FAILED.')
        
        print(' + hmac_sha1_80 authentication')
        try:
            assert o.AE_hmac_sha1_80(salt, pw) == b'j|\xB9\xA9\xEE3#\x00|\x17'
        except:
            print('   FAILED.')

        print(' + AES encryption')
        try:
            assert o.AE_ctr_crypt(salt, pw) == b'\x8A\x8Ar\xFB\xFAA\xE0\xCA'
            T = timeit.timeit('o.AE_ctr_crypt(salt, (16<<20)*b"x")', setup='from __main__ import o, salt', number=1)
            print('AE_ctr_crypt performed @%.3f KiB/s on 16 MiB block' % ((16<<20)/1024.0/T))
        except:
            print('   FAILED.')

    print('DONE.')
