# A micro reader & writer for AES encrypted ZIP archives
# Writes with AES-256 encryption, decrypts with smaller keys, too
# Based on Python 2.7 x86. It requires one of the cypto toolkits
# pycrypto, libeay32 from OpenSSL, botan or NSS from Mozilla
import zlib, struct, time

# 0=Nessuno, 1=pycrypto, 2=libeay, 3=botan, 4=nss3
CRYPTO_KIT = 0

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto import Random, Util
    
    CRYPTO_KIT = 1
except:
    pass


if not CRYPTO_KIT:
    try:
        from ctypes import *
        cryptodl = CDLL('libeay32')
        CRYPTO_KIT = 2

        # Nel modo CTR il cifrato risulta dallo XOR tra ciascun blocco di testo in chiaro e un contatore cifrato in modo ECB
        # realizzato, preferibilmente, mediante unione di n bit casuali con n bit di contatore.
        # I protocolli AE-1 e AE-2 di WinZip richiedono che il contatore sia un numero a 128 bit codificato in Little Endian
        # diversamente dalle maggiori implementazioni in Big Endian; inoltre il contatore parte da 1 senza
        # alcun contenuto casuale.
        # NOTA: la versione C e' veloce quanto quella pycrypto
        def AES_ctr128_le_crypt(key, s):
            if not s: return ''
            # La chiave deve avere 128, 192 o 256 bit
            if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")
            AES_KEY = create_string_buffer(244)
            assert cryptodl.AES_set_encrypt_key(key, len(key)*8, AES_KEY) == 0
            ctr_counter_le, ctr_encrypted_counter = create_string_buffer(16), create_string_buffer(16)
            # In nessun caso un elemento di un archivio ZIP non ZIP64 supera i 4 GiB
            # Possiamo usare tranquillamente solo la prima DWORD come contatore
            ptr = cast(ctr_counter_le, POINTER(c_ulong))
            es = ''
            i = 1 # il contatore parte da 1
            for i in range(i, (len(s)/16)+1):
                j = (i-1)*16
                ptr.contents.value += 1
                # Cifra il valore corrente del contatore
                cryptodl.AES_ecb_encrypt(ctr_counter_le, ctr_encrypted_counter, AES_KEY, 1)
                # Esegue (lentamente!) lo XOR con il testo in chiaro, 64 bit alla volta
                # 72x slower than pycrypto
                for k in range(16):
                    es += chr(ord(ctr_encrypted_counter.raw[k]) ^ ord(s[j+k]))
                # 88x slower than pycrypto
                #~ for k in range(0, 16, 8):
                    #~ a = cast(ctr_encrypted_counter.raw[k:k+8], POINTER(c_ulonglong)).contents.value
                    #~ b = cast(s[j+k:j+k+8], POINTER(c_ulonglong)).contents.value
                    #~ es += string_at(byref(c_ulonglong(a^b)),8)
            # Elabora il blocco parziale eventualmente residuato
            j = len(s)%16
            if j:
                #~ ctr_counter_le[0:4] = string_at(byref(c_uint(i+1)), 4)
                ptr.contents.value += 1
                cryptodl.AES_ecb_encrypt(ctr_counter_le, ctr_encrypted_counter, AES_KEY, 1)
                for k in range(j):
                    es += chr(ord(ctr_encrypted_counter.raw[k]) ^ ord(s[-j+k]))
            return es

        # Se presente, sostituisce con la versione C
        import _libeay
        AES_ctr128_le_crypt = _libeay.AES_ctr128_le_crypt
    except:
        pass


if not CRYPTO_KIT:
    try:
        from ctypes import *
        cryptodl = CDLL('botan')
        CRYPTO_KIT = 3
    except:
        pass


if not CRYPTO_KIT:
    try:
        from ctypes import *
        cryptodl = CDLL('nss3')
        cryptodl.NSS_NoDB_Init(".")
        # Servono almeno le DLL nss3, softokn3, freebl3, mozglue
        if not cryptodl.NSS_IsInitialized():
            raise Exception("NSS3 INITIALIZATION FAILED")
        CRYPTO_KIT = 4
    except:
        pass
        

if not CRYPTO_KIT:
    raise Exception("CAN'T RUN - NONE OF THE SUPPORTED CRYPTO KIT IS PRESENT!")

    
if CRYPTO_KIT == 1:
    def AE_gen_salt():
        "Genera 128 bit casuali di salt per AES-256"
        return Random.get_random_bytes(16)

    def AE_derive_keys(password, salt):
        "Con la password ZIP e il salt casuale, genera le chiavi per AES \
       e HMAC-SHA1-80, e i 16 bit di controllo"
        keylen = {8:16,12:24,16:32}[len(salt)]
        s = PBKDF2(password, salt, 2*keylen+2)
        return s[:keylen], s[keylen:2*keylen], s[2*keylen:]

    def AE_ctr_crypt(key, s):
        "Cifra/decifra in AES-256 CTR con contatore Little Endian"
        enc = AES.new(key, AES.MODE_CTR, counter=Util.Counter.new(128, little_endian=True))
        return enc.encrypt(s)

    def AE_hmac_sha1_80(key, s):
        "Autentica con HMAC-SHA1-80"
        hmac = HMAC.new(key, digestmod=SHA)
        hmac.update(s)
        return hmac.digest()[:10]
        
elif CRYPTO_KIT == 2:
    
    def AE_gen_salt():
        "Genera 128 bit casuali di salt per AES-256"
        key = create_string_buffer(16)
        cryptodl.RAND_poll()
        cryptodl.RAND_screen()
        if not cryptodl.RAND_bytes(key, 16):
            cryptodl.RAND_pseudo_bytes(key, 16)
        return key.raw

    def AE_derive_keys(password, salt):
        "Con la password ZIP e il salt casuale, genera le chiavi per AES \
        e HMAC-SHA1-80, e i 16 bit di controllo"
        keylen = {8:16,12:24,16:32}[len(salt)]
        s = create_string_buffer(2*keylen+2)
        cryptodl.PKCS5_PBKDF2_HMAC_SHA1(password, len(password), salt, len(salt), 1000, 2*keylen+2, s)
        return s.raw[:keylen], s.raw[keylen:2*keylen], s.raw[2*keylen:]

    def AE_ctr_crypt(key, s):
        "Cifra/decifra in AES-256 CTR con contatore Little Endian"
        return AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(key, s):
        "Autentica con HMAC-SHA1-80"
        digest = cryptodl.HMAC(cryptodl.EVP_sha1(), key, len(key), s, len(s), 0, 0);    
        return string_at(digest)[:10]
    
elif CRYPTO_KIT == 3:

    def AES_ctr128_le_crypt(key, s):
            if not s: return ''
            # La chiave deve avere 128, 192 o 256 bit
            if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")

            cipher = c_void_p(0)
            cryptodl.botan_cipher_init(byref(cipher), 'AES-256/ECB', 0)
            cryptodl.botan_cipher_set_key(cipher, key, len(key))

            ctr_counter_le, ctr_encrypted_counter = create_string_buffer(16), create_string_buffer(16)
            # In nessun caso un elemento di un archivio ZIP non ZIP64 supera i 4 GiB
            # Possiamo usare tranquillamente solo la prima DWORD come contatore
            ptr = cast(ctr_counter_le, POINTER(c_ulong))
            es = ''
            i = 1 # il contatore parte da 1
            for i in range(i, (len(s)/16)+1):
                j = (i-1)*16
                ptr.contents.value += 1
                # Cifra il valore corrente del contatore
                o0, i0 = c_size_t(0), c_size_t(0)
                cryptodl.botan_cipher_update(cipher, c_uint32(1), ctr_encrypted_counter, 16, byref(o0), ctr_counter_le, 16, byref(i0))
                # Esegue (lentamente!) lo XOR con il testo in chiaro, 64 bit alla volta
                # 72x slower than pycrypto
                for k in range(16):
                    es += chr(ord(ctr_encrypted_counter.raw[k]) ^ ord(s[j+k]))
            # Elabora il blocco parziale eventualmente residuato
            j = len(s)%16
            if j:
                ptr.contents.value += 1
                o0, i0 = c_size_t(0), c_size_t(0)
                cryptodl.botan_cipher_update(cipher, c_uint32(1), ctr_encrypted_counter, 16, byref(o0), ctr_counter_le, 16, byref(i0))
                for k in range(j):
                    es += chr(ord(ctr_encrypted_counter.raw[k]) ^ ord(s[-j+k]))
            return es

    def AE_gen_salt():
        "Genera 128 bit casuali di salt per AES-256"
        key = create_string_buffer(16)
        rng = c_void_p(0)
        cryptodl.botan_rng_init(byref(rng), 'system')
        cryptodl.botan_rng_get(rng, key, c_size_t(16))
        return key.raw

    def AE_derive_keys(password, salt):
        "Con la password ZIP e il salt casuale, genera le chiavi per AES \
        e HMAC-SHA1-80, e i 16 bit di controllo"
        keylen = {8:16,12:24,16:32}[len(salt)]
        s = create_string_buffer(2*keylen+2)
        cryptodl.botan_pbkdf('PBKDF2(SHA-1)', s, 2*keylen+2, password, salt, len(salt), 1000)
        return s.raw[:keylen], s.raw[keylen:2*keylen], s.raw[2*keylen:]

    def AE_ctr_crypt(key, s):
        "Cifra/decifra in AES-256 CTR con contatore Little Endian"
        return AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(key, s):
        "Autentica con HMAC-SHA1-80"
        digest = create_string_buffer(20)
        mac = c_void_p(0)
        cryptodl.botan_mac_init(byref(mac), 'HMAC(SHA-1)', 0)
        cryptodl.botan_mac_set_key(mac, key, len(key))
        cryptodl.botan_mac_update(mac, s, len(s))
        cryptodl.botan_mac_final(mac, digest)
        return string_at(digest)[:10]

elif CRYPTO_KIT == 4:
    
    # In lib\util\seccommon.h
    class SECItemStr(Structure):
        _fields_ = [('SECItemType', c_uint), ('data', POINTER(c_char)), ('len', c_uint)]

    def AES_ctr128_le_crypt(key, s):
            if not s: return ''
            # La chiave deve avere 128, 192 o 256 bit
            if len(key) not in (16,24,32):
                raise Exception("BAD AES KEY LENGTH %d BYTES" % len(key))

            # In nss\lib\util\pkcs11t.h: CKM_AES_ECB = 0x1081
            slot = cryptodl.PK11_GetBestSlot(0x1081, 0)
            
            ki = SECItemStr()
            ki.SECItemType = 0 # type siBuffer
            # Esiste un modo migliore? Purtroppo .data non puo' essere c_char_p
            # in quanto troncherebbe al primo NULL
            ki.data = (c_char*len(key)).from_buffer_copy(key)
            ki.len = len(key)
            
            # PK11_OriginUnwrap = 4
            # CKA_ENCRYPT = 0x104
            sk = cryptodl.PK11_ImportSymKey(slot, 0x1081, 4, 0x104, byref(ki), 0)
            sp = cryptodl.PK11_ParamFromIV(0x1081, 0)
            ctxt = cryptodl.PK11_CreateContextBySymKey(0x1081, 0x104, sk, sp)
            
            ctr_counter_le, ctr_encrypted_counter = create_string_buffer(16), create_string_buffer(16)
            # In nessun caso un elemento di un archivio ZIP non ZIP64 supera i 4 GiB
            # Possiamo usare tranquillamente solo la prima DWORD come contatore
            ptr = cast(ctr_counter_le, POINTER(c_ulong))
            es = ''
            i = 1 # il contatore parte da 1
            olen = c_uint32(0)
            for i in range(i, (len(s)/16)+1):
                j = (i-1)*16
                ptr.contents.value += 1
                # Cifra il valore corrente del contatore
                cryptodl.PK11_CipherOp(ctxt, ctr_encrypted_counter, byref(olen), 16, ctr_counter_le, 16)
                # Esegue (lentamente!) lo XOR con il testo in chiaro, 64 bit alla volta
                # 72x slower than pycrypto
                for k in range(16):
                    es += chr(ord(ctr_encrypted_counter.raw[k]) ^ ord(s[j+k]))
            # Elabora il blocco parziale eventualmente residuato
            j = len(s)%16
            if j:
                ptr.contents.value += 1
                cryptodl.PK11_CipherOp(ctxt, ctr_encrypted_counter, byref(olen), 16, ctr_counter_le, 16)
                # Non serve, dato che la dimensione di ctr_counter_le eguaglia sempre il blocco AES
                #~ cryptodl.PK11_DigestFinal(ctxt, ctr_encrypted_counter, byref(olen), 16-olen.value)
                for k in range(j):
                    es += chr(ord(ctr_encrypted_counter.raw[k]) ^ ord(s[-j+k]))
                    
            cryptodl.PK11_DestroyContext(ctxt, 1)
            cryptodl.PK11_FreeSymKey(sk)
            cryptodl.PK11_FreeSlot(slot)
            
            return es

    def AE_gen_salt():
        "Genera 128 bit casuali di salt per AES-256"
        key = create_string_buffer(16)
        cryptodl.PK11_GenerateRandom(key, 16)
        return key.raw

    def AE_derive_keys(password, salt):
        "Con la password ZIP e il salt casuale, genera le chiavi per AES \
      e HMAC-SHA1-80, e i 16 bit di controllo"
        keylen = {8:16,12:24,16:32}[len(salt)]
        
        si = SECItemStr()
        si.SECItemType = 0 # type siBuffer
        si.data = (c_char*len(salt)).from_buffer_copy(salt)
        si.len = len(salt)

        # SEC_OID_PKCS5_PBKDF2 = 291
        # SEC_OID_HMAC_SHA1 = 294
        algid = cryptodl.PK11_CreatePBEV2AlgorithmID(291, 291, 294, 2*keylen+2, 1000, byref(si))

        # CKM_PKCS5_PBKD2 = 0x3B0
        slot = cryptodl.PK11_GetBestSlot(0x3B0, 0)
        
        pi = SECItemStr()
        pi.SECItemType = 0 # type siBuffer
        pi.data = (c_char*len(password)).from_buffer_copy(password)
        pi.len = len(password)
        
        sk = cryptodl.PK11_PBEKeyGen(slot, algid, byref(pi), 0, 0)
        cryptodl.PK11_ExtractKeyValue(sk)
        pkd = cryptodl.PK11_GetKeyData(sk)
        rawkey = cast(pkd, POINTER(SECItemStr)).contents.data[:2*keylen+2]
        a,b,c = rawkey[:keylen], rawkey[keylen:2*keylen], rawkey[2*keylen:] 
        cryptodl.PK11_FreeSymKey(sk)
        cryptodl.PK11_FreeSlot(slot)
        return a, b, c

    def AE_ctr_crypt(key, s):
        "Cifra/decifra in AES-256 CTR con contatore Little Endian"
        return AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(key, s):
        "Autentica con HMAC-SHA1-80"
        ki = SECItemStr()
        ki.SECItemType = 0 # type siBuffer
        ki.data = (c_char*len(key)).from_buffer_copy(key)
        ki.len = len(key)

        # In lib\util\pkcs11t.h
        #define CKM_SHA_1_HMAC         0x00000221
        #define CKA_SIGN               0x00000108
        slot = cryptodl.PK11_GetBestSlot(0x221, 0)
        # PK11_OriginUnwrap = 4
        sk = cryptodl.PK11_ImportSymKey(slot, 0x221, 4, 0x108, byref(ki), 0)

        np = SECItemStr()
        ctxt = cryptodl.PK11_CreateContextBySymKey(0x221, 0x108, sk, byref(np))
        cryptodl.PK11_DigestBegin(ctxt)
        cryptodl.PK11_DigestOp(ctxt, s, len(s))
        digest = create_string_buffer(20)
        length = c_uint32(0)
        cryptodl.PK11_DigestFinal(ctxt, digest, byref(length), 20)

        cryptodl.PK11_DestroyContext(ctxt, 1)
        cryptodl.PK11_FreeSymKey(sk)
        cryptodl.PK11_FreeSlot(slot)

        return digest.raw[:10]
        
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
        p.salt = AE_gen_salt()
        p.aes_key, p.hmac_key, p.chkword = AE_derive_keys(password, p.salt)
        
    def append(p, entry, s):
        # Nome del file da aggiungere
        p.entry = entry
        # Calcola il CRC-32 sui dati originali
        p.crc32 = zlib.crc32(s) & 0xFFFFFFFF
        # Comprime, cifra e calcola l'hash sul cifrato
        cs = p.compressor.compress(s) + p.compressor.flush()
        # csize = salt (16) + chkword (2) + len(s) + HMAC (10)
        p.usize, p.csize = len(s), len(cs)+28
        p.blob = AE_ctr_crypt(p.aes_key, cs)

    def write(p):
        p.fp.write(p.PK0304())
        p.fp.write(p.salt)
        p.fp.write(p.chkword)
        p.fp.write(p.blob)
        p.fp.write(AE_hmac_sha1_80(p.hmac_key, p.blob))
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
        aes_key, hmac_key, chkword = AE_derive_keys(password, p.salt)
        if p.chkword != chkword:
            raise Exception("BAD PASSWORD")
        if p.digest != AE_hmac_sha1_80(hmac_key, p.blob):
            raise Exception("BAD HMAC-SHA1-80")
        cs = AE_ctr_crypt(aes_key, p.blob)
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
    import StringIO
    f = StringIO.StringIO()
    zip = MiniZipAE1Writer(f, 'password')
    zip.append('a.txt', 'CIAO')
    zip.write()
    
    f.seek(0,0)

    zip = MiniZipAE1Reader(f, 'password')
    assert 'CIAO' == zip.get()
    print 'TEST PASSED!'
