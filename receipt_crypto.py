"""P-256/SHA-256 signatures through native libraries, no pip dependencies.

Darwin: Apple Security/CoreFoundation. Linux: system OpenSSL 3 test backend.
No portable handwritten elliptic-curve arithmetic and no command-line signer.
Private keys MUST stay outside synchronized trees. Public trust is enrolled,
never inferred from a public key sent along with a signed receipt.
"""
from __future__ import annotations
import base64
import contextlib
import ctypes as C
import hashlib
import sys

ALGORITHM = 'ECDSA-P256-SHA256-DER'
DOMAIN = b'GDOE-SIGNED-RECEIPT-V1\x00'
SPKI_PREFIX = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')

class CryptoError(Exception):
    pass

def _check(value, message='Native cryptographic operation failed'):
    if not value:
        raise CryptoError(message)
    return value

def public_id(public: bytes) -> str:
    if len(public) != 65 or public[0] != 4:
        raise CryptoError('Expected uncompressed P-256 public key')
    return hashlib.sha256(b'GDOE-P256-PUBLIC-V1\x00' + public).hexdigest()

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')

def unb64(value: str, maximum: int = 65536) -> bytes:
    if not isinstance(value, str) or len(value) > 4*((maximum+2)//3):
        raise CryptoError('Invalid or oversized base64 field')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as e:
        raise CryptoError('Invalid base64') from e
    if len(raw) > maximum or b64(raw) != value:
        raise CryptoError('Noncanonical base64')
    return raw

class OpenSSLBackend:
    name = 'openssl3-linux'
    private_format = 'openssl-ec-private-der'
    def __init__(self):
        if sys.platform != 'linux':
            raise CryptoError('OpenSSL test backend is Linux-only')
        try:
            self.lib = C.CDLL('libcrypto.so.3')
            def fn(name, result, args):
                f = getattr(self.lib, name); f.restype = result; f.argtypes = args
                setattr(self, name, f)
            P, S, I = C.c_void_p, C.c_size_t, C.c_int
            fn('EVP_PKEY_Q_keygen', P, [P,C.c_char_p,C.c_char_p]) # EC vararg follows fixed args
            fn('EVP_PKEY_free', None, [P])
            fn('i2d_PrivateKey', I, [P,C.POINTER(P)])
            fn('d2i_AutoPrivateKey', P, [C.POINTER(P),C.POINTER(P),C.c_long])
            fn('d2i_PUBKEY', P, [C.POINTER(P),C.POINTER(P),C.c_long])
            fn('EVP_PKEY_get_octet_string_param', I, [P,C.c_char_p,P,S,C.POINTER(S)])
            fn('EVP_MD_CTX_new', P, [])
            fn('EVP_MD_CTX_free', None, [P])
            fn('EVP_sha256', P, [])
            fn('EVP_DigestSignInit', I, [P,C.POINTER(P),P,P,P])
            fn('EVP_DigestSign', I, [P,P,C.POINTER(S),P,S])
            fn('EVP_DigestVerifyInit', I, [P,C.POINTER(P),P,P,P])
            fn('EVP_DigestVerify', I, [P,P,S,P,S])
        except (OSError,AttributeError) as e:
            raise CryptoError('System OpenSSL 3 signature backend unavailable') from e

    @contextlib.contextmanager
    def _key(self, raw: bytes, private: bool):
        buf = C.create_string_buffer(raw); ptr = C.c_void_p(C.addressof(buf))
        key = (self.d2i_AutoPrivateKey if private else self.d2i_PUBKEY)(None,C.byref(ptr),len(raw))
        _check(key,'Invalid encoded EC key')
        try:
            _check(ptr.value == C.addressof(buf)+len(raw),'Trailing key data')
            yield key
        finally: self.EVP_PKEY_free(key)

    def _public(self, key):
        buf=C.create_string_buffer(65); length=C.c_size_t()
        _check(self.EVP_PKEY_get_octet_string_param(key,b'pub',buf,65,C.byref(length)) == 1)
        _check(length.value==65 and buf.raw[0]==4)
        return buf.raw

    def generate(self) -> tuple[bytes, bytes]:
        key = _check(self.EVP_PKEY_Q_keygen(None,None,b'EC',C.c_char_p(b'prime256v1')))
        try:
            n=self.i2d_PrivateKey(key,None); _check(0<n<4096)
            buf=C.create_string_buffer(n); ptr=C.c_void_p(C.addressof(buf))
            _check(self.i2d_PrivateKey(key,C.byref(ptr))==n)
            return buf.raw,self._public(key)
        finally: self.EVP_PKEY_free(key)

    def public_from_private(self, raw: bytes) -> bytes:
        with self._key(raw,True) as key: return self._public(key)

    def sign(self, private: bytes, data: bytes) -> bytes:
        with self._key(private,True) as key:
            ctx=_check(self.EVP_MD_CTX_new())
            try:
                _check(self.EVP_DigestSignInit(ctx,None,self.EVP_sha256(),None,key)==1)
                n=C.c_size_t(); msg=C.create_string_buffer(data)
                _check(self.EVP_DigestSign(ctx,None,C.byref(n),msg,len(data))==1)
                _check(8<=n.value<=80)
                buf=C.create_string_buffer(n.value)
                _check(self.EVP_DigestSign(ctx,buf,C.byref(n),msg,len(data))==1)
                return buf.raw[:n.value]
            finally: self.EVP_MD_CTX_free(ctx)

    def verify(self, public: bytes, data: bytes, signature: bytes) -> bool:
        public_id(public)
        if not 8<=len(signature)<=80: return False
        with self._key(SPKI_PREFIX+public,False) as key:
            ctx=_check(self.EVP_MD_CTX_new())
            try:
                _check(self.EVP_DigestVerifyInit(ctx,None,self.EVP_sha256(),None,key)==1)
                return self.EVP_DigestVerify(ctx,C.create_string_buffer(signature),len(signature),
                    C.create_string_buffer(data),len(data))==1
            finally: self.EVP_MD_CTX_free(ctx)

class DarwinBackend:
    name = 'apple-security'
    private_format = 'apple-p256-x963-private'
    def __init__(self):
        if sys.platform!='darwin': raise CryptoError('Apple Security backend is Darwin-only')
        try:
            self.cf=C.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
            self.sec=C.CDLL('/System/Library/Frameworks/Security.framework/Security')
            P=C.c_void_p; L=C.c_long
            for lib,name,rt,args in [
                (self.cf,'CFRelease',None,[P]),
                (self.cf,'CFDataCreate',P,[P,P,L]),
                (self.cf,'CFDataGetLength',L,[P]),
                (self.cf,'CFDataGetBytePtr',P,[P]),
                (self.cf,'CFNumberCreate',P,[P,C.c_int,P]),
                (self.cf,'CFDictionaryCreateMutable',P,[P,L,P,P]),
                (self.cf,'CFDictionarySetValue',None,[P,P,P]),
                (self.sec,'SecKeyCreateRandomKey',P,[P,C.POINTER(P)]),
                (self.sec,'SecKeyCopyPublicKey',P,[P]),
                (self.sec,'SecKeyCopyExternalRepresentation',P,[P,C.POINTER(P)]),
                (self.sec,'SecKeyCreateWithData',P,[P,P,C.POINTER(P)]),
                (self.sec,'SecKeyCreateSignature',P,[P,P,P,C.POINTER(P)]),
                (self.sec,'SecKeyVerifySignature',C.c_ubyte,[P,P,P,P,C.POINTER(P)])]:
                f=getattr(lib,name); f.restype=rt; f.argtypes=args; setattr(self,name,f)
            self.algorithm=self._constant('kSecKeyAlgorithmECDSASignatureMessageX962SHA256')
        except (OSError,AttributeError,ValueError) as e:
            raise CryptoError('Apple Security signature API unavailable') from e

    def _constant(self,name): return C.c_void_p.in_dll(self.sec,name).value
    def _release(self,*values):
        for value in values:
            if value: self.CFRelease(value)
    def _data(self,data):
        return _check(self.CFDataCreate(None,C.create_string_buffer(data),len(data)))
    def _bytes(self,data):
        n=self.CFDataGetLength(data); _check(0<=n<=4096)
        return C.string_at(self.CFDataGetBytePtr(data),n)
    @contextlib.contextmanager
    def _attributes(self,private: bool):
        # NULL callbacks: this short-lived dictionary borrows static constants
        # and our number, all retained until the synchronous Security call returns.
        attrs=_check(self.CFDictionaryCreateMutable(None,0,None,None))
        number=None
        try:
            bits=C.c_int(256); number=_check(self.CFNumberCreate(None,9,C.byref(bits))) # kCFNumberIntType
            for k,v in [('kSecAttrKeyType',self._constant('kSecAttrKeyTypeECSECPrimeRandom')),
                        ('kSecAttrKeyClass',self._constant('kSecAttrKeyClassPrivate' if private else 'kSecAttrKeyClassPublic')),
                        ('kSecAttrKeySizeInBits',number)]:
                self.CFDictionarySetValue(attrs,self._constant(k),v)
            yield attrs
        finally: self._release(attrs,number)
    @contextlib.contextmanager
    def _key(self,raw,private):
        _check(len(raw)==(97 if private else 65) and raw[0]==4,'Invalid P-256 X9.63 key length')
        data=self._data(raw); err=C.c_void_p(); key=None
        try:
            with self._attributes(private) as attrs:
                key=_check(self.SecKeyCreateWithData(data,attrs,C.byref(err)),'Invalid EC key')
            yield key
        finally: self._release(key,data,err.value)
    def _external(self,key):
        err=C.c_void_p(); data=None
        try:
            data=_check(self.SecKeyCopyExternalRepresentation(key,C.byref(err)))
            return self._bytes(data)
        finally: self._release(data,err.value)
    def generate(self):
        err=C.c_void_p(); key=pub=None
        try:
            with self._attributes(True) as attrs:
                key=_check(self.SecKeyCreateRandomKey(attrs,C.byref(err)))
            pub=_check(self.SecKeyCopyPublicKey(key))
            private,public=self._external(key),self._external(pub)
            _check(len(private)==97 and len(public)==65)
            return private,public
        finally: self._release(key,pub,err.value)
    def public_from_private(self,raw):
        with self._key(raw,True) as key:
            pub=_check(self.SecKeyCopyPublicKey(key))
            try: return self._external(pub)
            finally: self._release(pub)
    def sign(self,private,data):
        with self._key(private,True) as key:
            message=self._data(data); signature=None; err=C.c_void_p()
            try:
                signature=_check(self.SecKeyCreateSignature(key,self.algorithm,message,C.byref(err)))
                return self._bytes(signature)
            finally: self._release(message,signature,err.value)
    def verify(self,public,data,signature):
        public_id(public)
        if not 8<=len(signature)<=80: return False
        with self._key(public,False) as key:
            message=self._data(data); sig=self._data(signature); err=C.c_void_p()
            try: return bool(self.SecKeyVerifySignature(key,self.algorithm,message,sig,C.byref(err)))
            finally: self._release(message,sig,err.value)

def native_backend():
    if sys.platform=='darwin': return DarwinBackend()
    if sys.platform=='linux': return OpenSSLBackend()
    raise CryptoError('No supported native signature backend; no fallback')
