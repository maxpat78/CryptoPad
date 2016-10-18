#include "Python.h"

#include <pk11pub.h>
#include <seccomon.h>

#ifdef BYTE_ORDER_1234
void betole64(unsigned long long *x) {
*x = (*x & 0x00000000FFFFFFFF) << 32 | (*x & 0xFFFFFFFF00000000) >> 32;
*x = (*x & 0x0000FFFF0000FFFF) << 16 | (*x & 0xFFFF0000FFFF0000) >> 16;
*x = (*x & 0x00FF00FF00FF00FF) << 8  | (*x & 0xFF00FF00FF00FF00) >> 8;
}
#endif

/*
Nel modo CTR il cifrato risulta dallo XOR tra ciascun blocco di testo in chiaro
e un contatore cifrato in modo ECB, realizzato, preferibilmente, mediante unione
di n bit casuali con n bit di contatore.

Il protocollo AE di WinZip richiede che il contatore sia un numero a 128 bit
codificato Little Endian diversamente dalle maggiori implementazioni: esso
parte da 1, senza alcun contenuto casuale. */
static PyObject *
p_AES_ctr128_le_crypt(self, args)
PyObject *self, *args;
{
	char ctr_counter_le[16];
	char ctr_encrypted_counter[16];
#ifdef BYTE_ORDER_1234
	char ctr_counter_be[16];
#endif
	const char* p = ctr_encrypted_counter;
	const char* q = p+8;
	char *key, *buf, *pbuf, *ppbuf;
	unsigned int key_len, buf_len, i;

	// NSS specific
	SECItem ki;
	PK11SlotInfo* slot;
	PK11SymKey* sk = NULL;
	SECItem* sp = NULL;
	PK11Context* ctxt = NULL;
	int olen;

	if ( !PyArg_ParseTuple(args, "s#s#", &key, &key_len, &buf, &buf_len))
		return Py_BuildValue("s", NULL);

	//~ # In nss\lib\util\pkcs11t.h:
	//~ # CKM_AES_ECB = 0x1081
	slot = PK11_GetBestSlot(0x1081, 0);
	ki.type = 0; // siBuffer
	ki.data = key;
	ki.len = key_len;

	//~ # PK11_OriginUnwrap = 4
	//~ # CKA_ENCRYPT = 0x104
	sk = PK11_ImportSymKey(slot, 0x1081, 4, 0x104, &ki, 0);
	sp = PK11_ParamFromIV(0x1081, 0);
	ctxt = PK11_CreateContextBySymKey(0x1081, 0x104, sk, sp);
	
#ifdef BYTE_ORDER_1234
	memset(ctr_counter_be, 0, 16);
#else
	memset(ctr_counter_le, 0, 16);
#endif
	
	ppbuf = pbuf = PyMem_Malloc(buf_len);

	for (i=0; i < buf_len/16; i++) {
#ifndef BYTE_ORDER_1234
		(*((unsigned long long*) ctr_counter_le))++;
#else	
		(*((unsigned long long*) ctr_counter_be))++;
		*((unsigned long long*) ctr_counter_le) = *((unsigned long long*) ctr_counter_be);
		betole64((unsigned long long*)ctr_counter_le);
#endif
		PK11_CipherOp(ctxt, ctr_encrypted_counter, &olen, 16, ctr_counter_le, 16);
		*((unsigned long long*) pbuf)++ = *((unsigned long long*) buf)++ ^ *((unsigned long long*) p);
		*((unsigned long long*) pbuf)++ = *((unsigned long long*) buf)++ ^ *((unsigned long long*) q);
	}

	if ((i = buf_len%16)) {
#ifndef BYTE_ORDER_1234
		(*((unsigned long long*) ctr_counter_le))++;
#else	
		(*((unsigned long long*) ctr_counter_be))++;
		*((unsigned long long*) ctr_counter_le) = *((unsigned long long*) ctr_counter_be);
		betole64((unsigned long long*)ctr_counter_le);
#endif
		PK11_CipherOp(ctxt, ctr_encrypted_counter, &olen, 16, ctr_counter_le, 16);
		while (i--)
			*pbuf++ = *buf++ ^ *p++;
	}

	PK11_DestroyContext(ctxt, 1);
	PK11_FreeSymKey(sk);
	PK11_FreeSlot(slot);

#if PY_MAJOR_VERSION > 2
	return Py_BuildValue("y#", ppbuf, buf_len);
#else
	return Py_BuildValue("s#", ppbuf, buf_len);
#endif
}


static PyMethodDef _libnss_methods[] =
{
 {"AES_ctr128_le_crypt", p_AES_ctr128_le_crypt, METH_VARARGS, "Encrypts with AES CTR-LE (via NSS)"},
 {NULL, NULL, 0, NULL}
};


#if PY_MAJOR_VERSION > 2
static struct PyModuleDef _libnss_module = {
   PyModuleDef_HEAD_INIT,
   "_libnss",   /* name of module */
   NULL, /* module documentation, may be NULL */
   -1,       /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   _libnss_methods
};

PyMODINIT_FUNC PyInit__libnss()
{
 return PyModule_Create(&_libnss_module);
}
#else
__declspec(dllexport)
void
init_libnss()
{
 Py_InitModule("_libnss", _libnss_methods);
}
#endif
