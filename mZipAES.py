# A micro reader & writer for AES encrypted ZIP archives

# Encrypts in AES-256, decrypts with smaller keys, too

# Based on Python 3 x64. It requires one of the cypto toolkits/libraries:
# pycryptodome, libeay (libcrypto) from OpenSSL or LibreSSL, botan, (lib)NSS3
# from Mozilla or GNU libgcrypt.

"""
/*
 *  Copyright (C) 2015-2023, maxpat78 <https://github.com/maxpat78>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
"""

from __future__ import print_function
import zlib, struct, time, sys, os
from ctypes import *
from ctypes.util import find_library

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto import Random
    from Crypto.Util import Counter
    PYCRYPTOAVAILABLE=1
except:
    PYCRYPTOAVAILABLE=0

def find_crypto(p, libs):
    p.loaded = 0
    lib = list(filter(find_library, libs))
    try:
        if lib:
            lib = os.path.abspath(find_library(lib[0]))
            p.handle = CDLL(lib)
            p.loaded = 1
    except:
        return
    


class Crypto_Class:
    def __init__(p):
        pass

    def AE_gen_salt(p):
        "Returns a 128-bits random salt for use with AES-256"
        pass

    def AE_derive_keys(p, password, salt):
        """Given the password and the random salt, it generates the keys for
        AES encryption and HMAC-SHA1-80 authentication, plus 2 control bytes
        required by ZIP AE specification"""
        pass

    def AE_ctr_crypt(p, key, s):
        """De/en-ciphers in one pass 's' with 'key', using AES-256 in CTR mode
        with a Little-Endian 128-bit counter"""
        pass

    def AE_hmac_sha1_80(p, key, s):
        "Authenticates 's' with HMAC-SHA1-80"
        pass



class Crypto_PyCryptodome(Crypto_Class):
    KitName = 'PyCryptodome 3.17.0+'
    
    def __init__(p):
        p.loaded = PYCRYPTOAVAILABLE
        if not p.loaded: return None

    def AE_gen_salt(p):
        return Random.get_random_bytes(16)

    def AE_derive_keys(p, password, salt):
        keylen = {8:16,12:24,16:32}[len(salt)]
        if sys.version_info >= (3,0) and type(password)!=type(b''):
            password = bytes(password, 'utf8')
        s = PBKDF2(password, salt, 2*keylen+2)
        return s[:keylen], s[keylen:2*keylen], s[2*keylen:]

    def AE_ctr_crypt(p, key, s):
        enc = AES.new(key, AES.MODE_CTR, counter=Counter.new(128, little_endian=True))
        return enc.encrypt(s)

    def AE_hmac_sha1_80(p, key, s):
        hmac = HMAC.new(key, digestmod=SHA)
        hmac.update(s)
        return hmac.digest()[:10]



class Crypto_OpenSSL(Crypto_Class):
    KitName = 'OpenSSL 1.0.2+/LibreSSL'
    
    def __init__(p):
        libs = ['libcrypto.so', 'libcrypto.so.1.0.0', 'libcrypto-1_1', 'crypto-50']
        find_crypto(p, libs)

        if p.handle:
            x = p.handle
            # We need these in x64 since c_void_p != c_int and right size can't be guessed automatically
            x.HMAC.argtypes = [c_void_p, c_void_p, c_int, c_char_p, c_size_t, c_void_p, c_void_p]
            x.HMAC.restype = c_void_p
            x.EVP_sha1.restype = c_void_p

        # Replaces with the C implementation, if available
        try:
            import _libeay
            p.AES_ctr128_le_crypt = _libeay.AES_ctr128_le_crypt
        except:
            pass

    """ In the WinZip AE CTR mode, each block is the XOR between the plain
    text and a 128 bit Little-Endian counter crypted in ECB mode (it starts
    from 1 and there are no random bits in the high QWORD).
    C implementation is as fast as pycryptodome, while this hybrid one is at
    least 35x slower due to ctypes calls/conversions.
    Also Python 3.4 was 1.6x slower than 2.7! """
    def AES_ctr128_le_crypt(p, key, s):
        if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")
        AES_KEY = create_string_buffer(244)
        p.handle.AES_set_encrypt_key(key, len(key)*8, AES_KEY)
        
        buf = (c_byte*len(s)).from_buffer_copy(s)
        
        ctr = create_string_buffer(16)
        ectr = create_string_buffer(16)
        pectr = cast(ectr, POINTER(c_byte))
        cnt = 0
        j = 0
        fuAES = p.handle.AES_ecb_encrypt
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
        key = create_string_buffer(16)
        p.handle.RAND_poll()
        if not p.handle.RAND_bytes(key, 16):
            p.handle.RAND_pseudo_bytes(key, 16)
        return key.raw

    def AE_derive_keys(p, password, salt):
        keylen = {8:16,12:24,16:32}[len(salt)]
        if sys.version_info >= (3,0) and type(password)!=type(b''):
            password = bytes(password, 'utf8')
        s = create_string_buffer(2*keylen+2)
        p.handle.PKCS5_PBKDF2_HMAC_SHA1(password, len(password), salt, len(salt), 1000, 2*keylen+2, s)
        return s.raw[:keylen], s.raw[keylen:2*keylen], s.raw[2*keylen:]

    def AE_ctr_crypt(p, key, s):
        return p.AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(p, key, s):
        digest = p.handle.HMAC(p.handle.EVP_sha1(), key, len(key), s, len(s), 0, 0)
        return cast(digest, POINTER(c_char*10)).contents.raw



class Crypto_Botan(Crypto_Class):
    KitName = 'Botan 2.19.3+'
    
    def __init__(p):
        libs = ['libbotan-2.19.so', 'botan']
        find_crypto(p, libs)

        try:
            import _libbotan
            p.AES_ctr128_le_crypt = _libbotan.AES_ctr128_le_crypt
        except:
            pass

    def AES_ctr128_le_crypt(self, key, s):
        if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")

        cipher = c_void_p(0)
        mode = {16:b'AES-128', 24:b'AES-192', 32:b'AES-256'}[len(key)]
        self.handle.botan_block_cipher_init(byref(cipher), mode)
        self.handle.botan_block_cipher_set_key(cipher, key, c_size_t(len(key)))
        
        buf = (c_byte*len(s)).from_buffer_copy(s)
        ctr = create_string_buffer(16)
        ectr = create_string_buffer(16)
        pectr = cast(ectr, POINTER(c_byte))
        cnt = 0
        j = 0
        fuAES = self.handle.botan_block_cipher_encrypt_blocks
        for i in range(len(s)):
            j=i%16
            if not j:
                cnt += 1
                struct.pack_into('<Q', ctr, 0, cnt)
                fuAES(cipher, ctr, ectr, c_size_t(1))
            buf[i] ^= pectr[j]
        if sys.version_info >= (3,0):
            return bytes(buf)
        else:
            return str(bytearray(buf))

    def AE_gen_salt(p):
        key = create_string_buffer(16)
        rng = c_void_p(0)
        p.handle.botan_rng_init(byref(rng), b'system')
        p.handle.botan_rng_get(rng, key, c_size_t(16))
        return key.raw

    def AE_derive_keys(p, password, salt):
        keylen = {8:16,12:24,16:32}[len(salt)]
        if sys.version_info >= (3,0) and type(password)!=type(b''):
            password = bytes(password, 'utf8')
        s = create_string_buffer(2*keylen+2)
        p.handle.botan_pbkdf(b'PBKDF2(SHA-1)', s, 2*keylen+2, password, salt, len(salt), 1000)
        return s.raw[:keylen], s.raw[keylen:2*keylen], s.raw[2*keylen:]

    def AE_ctr_crypt(p, key, s):
        return p.AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(p, key, s):
        digest = create_string_buffer(20)
        mac = c_void_p(0)
        p.handle.botan_mac_init(byref(mac), b'HMAC(SHA-1)', 0)
        p.handle.botan_mac_set_key(mac, key, len(key))
        p.handle.botan_mac_update(mac, s, len(s))
        p.handle.botan_mac_final(mac, digest)
        return cast(digest, POINTER(c_char*10)).contents.raw
    


class Crypto_NSS:
    KitName = 'Mozilla NSS3'
    
    # In lib\util\seccomon.h
    class SECItemStr(Structure):
        _fields_ = [('SECItemType', c_uint), ('data', POINTER(c_char)), ('len', c_uint)]

    def __init__(p):
        libs = ['libnss3.so', 'nss3']
        find_crypto(p, libs)
        p.loaded = 0
        try:
            p.handle.NSS_NoDB_Init(".")
            # At least nss3, softokn3, freebl3, mozglue DLLs are required
            if not p.handle.NSS_IsInitialized():
                raise Exception("NSS3 INITIALIZATION FAILED")
            p.loaded = 1
        except:
            pass

        try:
            import _libnss
            p.AES_ctr128_le_crypt = _libnss.AES_ctr128_le_crypt
        except:
            pass

        # We need these in x64 since c_void_p != c_int and right size can't be guessed automatically
        if p.handle:
            x = p.handle
            x.PK11_CreatePBEV2AlgorithmID.restype = c_void_p
            x.PK11_PBEKeyGen.argtypes = [c_void_p, c_void_p, c_void_p, c_int, c_void_p]
            x.PK11_FreeSymKey.argtypes = [c_void_p]
            x.PK11_FreeSlot.argtypes = [c_void_p]
            x.PK11_ParamFromIV.restype = c_void_p
            x.PK11_PBEKeyGen.restype = c_void_p
            x.PK11_ExtractKeyValue.argtypes = [c_void_p]
            x.PK11_ExtractKeyValue.restype = c_void_p
            x.PK11_GetKeyData.argtypes = [c_void_p]
            x.PK11_GetKeyData.restype = c_void_p
            x.PK11_GetBestSlot.restype = c_void_p
            x.PK11_ImportSymKey.argtypes = [c_void_p, c_int, c_int, c_int, c_void_p, c_void_p]
            x.PK11_ImportSymKey.restype = c_void_p
            x.PK11_CreateContextBySymKey.argtypes = [c_int, c_int, c_void_p, c_void_p]
            x.PK11_CreateContextBySymKey.restype = c_void_p
            x.PK11_CipherOp.argtypes = [c_void_p, c_void_p, c_void_p, c_int, c_void_p, c_int]
            x.PK11_DestroyContext.argtypes = [c_void_p]

    def AES_ctr128_le_crypt(self, key, s):
        if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")
        
        # In nss\lib\util\pkcs11t.h:
        # CKM_AES_ECB = 0x1081
        slot = self.handle.PK11_GetBestSlot(0x1081, 0)
        
        ki = self.SECItemStr()
        ki.SECItemType = 0 # type siBuffer
        # .data can't be c_char_p since it truncates at first NULL
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
        key = create_string_buffer(16)
        p.handle.PK11_GenerateRandom(key, 16)
        return key.raw

    def AE_derive_keys(p, password, salt):
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
        return p.AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(p, key, s):
        ki = p.SECItemStr()
        ki.SECItemType = 0 # type siBuffer
        ki.data = (c_char*len(key)).from_buffer_copy(key)
        ki.len = len(key)

        # In lib\util\pkcs11t.h
        # CKM_SHA_1_HMAC = 0x00000221
        # CKA_SIGN = 0x00000108
        slot = p.handle.PK11_GetBestSlot(0x221, c_void_p(0))
        # PK11_OriginUnwrap = 4
        sk = p.handle.PK11_ImportSymKey(slot, 0x221, 4, 0x108, byref(ki), 0)

        np = p.SECItemStr()
        ctxt = p.handle.PK11_CreateContextBySymKey(0x221, 0x108, sk, byref(np))
        p.handle.PK11_DigestBegin(c_void_p(ctxt))
        p.handle.PK11_DigestOp(c_void_p(ctxt), s, len(s))
        digest = create_string_buffer(20)
        length = c_uint32(0)
        p.handle.PK11_DigestFinal(c_void_p(ctxt), digest, byref(length), 20)

        p.handle.PK11_DestroyContext(c_void_p(ctxt), 1)
        p.handle.PK11_FreeSymKey(c_void_p(sk))
        p.handle.PK11_FreeSlot(c_void_p(slot))

        return digest.raw[:10]



class Crypto_GCrypt(Crypto_Class):
    KitName = 'GNU libgcrypt'
    
    def __init__(p):
        libs = ['libgcrypt-20.so', 'libgcrypt-20']
        find_crypto(p, libs)

        try:
            import _libgcrypt
            p.AES_ctr128_le_crypt = _libgcrypt.AES_ctr128_le_crypt
        except:
            pass
        
        if p.handle:
            x = p.handle
            x.gcry_random_bytes.restype = c_void_p
            x.gcry_mac_setkey.argtypes = [c_void_p, c_void_p, c_size_t]

    def AES_ctr128_le_crypt(self, key, s):
        if len(key) not in (16,24,32): raise Exception("BAD AES KEY LENGTH")

        hd = c_void_p(0)
        
        # GCRY_CIPHER_AESXXX = 7..9; GCRY_CIPHER_MODE_ECB=1 (OFB=5)
        self.handle.gcry_cipher_open(byref(hd), int(len(key)/8+5), 1, 0)
        self.handle.gcry_cipher_setkey(hd, key, len(key))

        buf = (c_byte*len(s)).from_buffer_copy(s)
        ctr = create_string_buffer(16)
        ectr = create_string_buffer(16)
        pectr = cast(ectr, POINTER(c_byte))
        cnt = 0
        j = 0
        fuAES = self.handle.gcry_cipher_encrypt
        for i in range(len(s)):
            j=i%16
            if not j:
                cnt += 1
                struct.pack_into('<Q', ctr, 0, cnt)
                fuAES(hd, ectr, 16, ctr, 16)
            buf[i] ^= pectr[j]

        self.handle.gcry_cipher_close(hd)

        if sys.version_info >= (3,0):
            return bytes(buf)
        else:
            return str(bytearray(buf))

    def AE_gen_salt(p):
        # GCRY_STRONG_RANDOM=1
        key = (c_char*16).from_address(p.handle.gcry_random_bytes(16, 1))
        return key.raw

    def AE_derive_keys(p, password, salt):
        keylen = {8:16,12:24,16:32}[len(salt)]
        if sys.version_info >= (3,0) and type(password)!=type(b''):
            password = bytes(password, 'utf8')
        s = create_string_buffer(2*keylen+2)
        #GCRY_KDF_PBKDF2 = 34; GCRY_MD_SHA1 = 2
        p.handle. gcry_kdf_derive(password, len(password), 34, 2, salt, len(salt), 1000, 2*keylen+2, s)
        return s.raw[:keylen], s.raw[keylen:2*keylen], s.raw[2*keylen:]

    def AE_ctr_crypt(p, key, s):
        return p.AES_ctr128_le_crypt(key, s)

    def AE_hmac_sha1_80(p, key, s):
        hd = c_void_p(0)
        # GCRY_MAC_HMAC_SHA1=105
        ret = p.handle.gcry_mac_open(byref(hd), 105, 0, 0)
        p.handle.gcry_mac_setkey(hd, key, len(key))
        p.handle.gcry_mac_write(hd, s, len(s))
        digest = create_string_buffer(20)
        l = c_long(20)
        p.handle.gcry_mac_read(hd, digest, byref(l))
        p.handle.gcry_mac_close(hd)
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

Extended AES header (both local & central) based on WinZip specs:

    extra field header      2 bytes  (0x9901)
    size                    2 bytes  (actually, 7)
    version                 2 bytes  (1 or 2)
    ZIP vendor              2 bytes  (actually, AE)
    strength                1 byte   (AES key bits: 1=128, 2=192, 3=256)
    actual compression      2 byte   (becomes 0x63 in LENT & CENT)

    content data, as follows:
    random salt (8, 12 or 16 byte depending on key size)
    2-byte password verification value (from PBKDF2 with SHA-1, 1000 rounds)
    AES encrypted data (CTR mode, little endian counter)
    10-byte authentication code for encrypted data from HMAC-SHA1

NOTE: AE-1 preserves CRC-32 on uncompressed data, AE-2 sets it to zero and
is used for plain data <20 bytes.

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
for C in (Crypto_PyCryptodome, Crypto_OpenSSL, Crypto_Botan, Crypto_NSS, Crypto_GCrypt):
    try:
        crypto_kit = C()
        if crypto_kit.loaded:
            break
    except:
        continue
if crypto_kit == None or not crypto_kit.loaded:
    raise Exception("NO CRYPTO KIT FOUND - ABORTED!")


class MiniZipAEWriter():
    def __init__ (p, stream, password):
        # Output stream to ZIP archive
        p.fp = stream
        # Starts zlib "raw" Deflate compressor
        p.compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        p.salt = crypto_kit.AE_gen_salt()
        p.aes_key, p.hmac_key, p.chkword = crypto_kit.AE_derive_keys(password, p.salt)
        p.AEv = 1 # AE revision
        p.crc = 0
        p.method = 8 # 0=Stored, 8=Deflated
        
    def append(p, entry, s):
        # Adds a file name
        if sys.version_info >= (3,0):
            p.entry = bytes(entry, 'utf8')
        else:
            p.entry = entry
        # Compresses, encrypts and gets the HMAC of the encrypted data
        cs = p.compressor.compress(s) + p.compressor.flush()
        if len(s) < 20:
            p.AEv = 2 # AE-2 does not store CRC-32
        else:
            p.crc = zlib.crc32(s) & 0xFFFFFFFF
        # csize = salt (16) + chkword (2) + len(s) + HMAC (10)
        if len(cs) >= len(s):
            cs = s
            p.usize, p.csize = len(s), len(s)+28
            p.method = 0
        else:
            p.usize, p.csize = len(s), len(cs)+28
        p.blob = crypto_kit.AE_ctr_crypt(p.aes_key, cs)

    def write(p):
        p.zipcomment = 'R' # denotes V2 document format
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
        return b'PK\x03\x04' + struct.pack('<5H3I2H', 0x33, 1, 99, 0, 33, p.crc, p.csize, p.usize, 4, 11) + b'data' + p.AEH()

    def AEH(p):
        return struct.pack('<4HBH', 0x9901, 7, p.AEv, 0x4541, 3, p.method)

    def PK0102(p):
        return b'PK\x01\x02' + struct.pack('<6H3I5H2I', 0x33, 0x33, 1, 99, 0, 33, p.crc, p.csize, p.usize, 4, 11, 0, 0, 0, 0x20, 0) + b'data' + p.AEH()

    def PK0506(p, cdirsize, offs):
        if hasattr(p, 'zipcomment'):
            if sys.version_info >= (3,0):
                p.zipcomment = bytes(p.zipcomment, 'utf8')
            return b'PK\x05\x06' + struct.pack('<4H2IH', 0, 0, 1, 1, cdirsize, offs, len(p.zipcomment)) + p.zipcomment
        else:
            return b'PK\x05\x06' + struct.pack('<4H2IH', 0, 0, 1, 1, cdirsize, offs, 0)


class MiniZipAEReader():
    def __init__ (p, stream, password):
        p.is_v2 = False
        p.fp = stream
        p.parse()
        aes_key, hmac_key, chkword = crypto_kit.AE_derive_keys(password, p.salt)
        if p.chkword != chkword:
            raise Exception("BAD PASSWORD")
        if p.digest != crypto_kit.AE_hmac_sha1_80(hmac_key, p.blob):
            raise Exception("BAD HMAC-SHA1-80")
        cs = crypto_kit.AE_ctr_crypt(aes_key, p.blob)
        if p.method == 0:
            p.s = cs
        else:
            p.s = zlib.decompressobj(-15).decompress(cs)
        if p.AEv == 1:
            crc = zlib.crc32(p.s) & 0xFFFFFFFF
            if crc != p.crc:
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
        ver1, flag, method, dtime, ddate, crc, csize, usize, namelen, xhlen = struct.unpack('<5H3I2H', p.fp.read(26))
        #~ print (ver1, flag, method, hex(dtime), hex(ddate), hex(crc32), csize, usize, namelen, xhlen)
        if method != 99:
            raise Exception("NOT AES ENCRYPTED")
        if xhlen != 11:
            raise Exception("TOO MANY EXT HEADERS")
        p.entry = p.fp.read(namelen)
        xh, cb, ver, vendor, keybits, method = struct.unpack('<4HBH', p.fp.read(xhlen))
        if xh != 0x9901 or ver not in (1,2) or vendor != 0x4541:
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
        p.crc = crc
        p.AEv = ver
        p.method = method # real method stored in AE header
        p.fp.seek(-1, 2)
        if p.fp.read(1) == b'R':
            p.is_v2 = True
        


if __name__ == '__main__':
    import io, timeit
    
    f = io.BytesIO()
    print('Testing MiniZipAE1Writer')
    zip = MiniZipAEWriter(f, 'password')
    zip.append('a.txt', 2155*b'CIAO')
    zip.write()
    
    f.seek(0,0)

    print('Testing MiniZipAE1Reader')
    zip = MiniZipAEReader(f, 'password')
    assert 2155*b'CIAO' == zip.get()

    salt = b'\x01' + b'\x00'*15
    pw = b'password'

    for C in (Crypto_Botan, Crypto_PyCryptodome, Crypto_NSS, Crypto_OpenSSL, Crypto_GCrypt):
        o = C
        try:
            o = o()
            if o.loaded:
                print('Testing', o.KitName)
            else:
                print(o.KitName, 'not available.')
                continue
        except:
            print(o.KitName, 'not available.')
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
            T = timeit.timeit('o.AE_hmac_sha1_80(salt, (16<<20)*b"x")', setup='from __main__ import o, salt', number=1)
            print('   AE_hmac_sha1_80 performed @%.3f KiB/s on a 16 MiB block' % ((16<<20)/1024.0/T))
        except:
            print('   FAILED.')

        print(' + AES encryption')
        try:
            # i7-6500U and Ryzen 5 1600 (hybrid): ~3 MB/s all except pycrypto
            # i7-6500U (C wrapper): GCrypt ~215 MB/s, Botan ~180 MB/s, libressl ~175 MB/s, pycrypto ~116 MB/s, NSS ~93 MB/s, openssl ~85 MB/s
            # Ryzen 5 1600 (C wrapper): pycryptodome ~968 MB/s, botan ~380 MB/s, libressl ~230 MB/s
            assert o.AE_ctr_crypt(salt, pw) == b'\x8A\x8Ar\xFB\xFAA\xE0\xCA'
            T = timeit.timeit('o.AE_ctr_crypt(salt, (16<<20)*b"x")', setup='from __main__ import o, salt', number=1)
            print('   AE_ctr_crypt performed @%.3f KiB/s on a 16 MiB block' % ((16<<20)/1024.0/T))
        except:
            print('   FAILED.')

    print('DONE.')
