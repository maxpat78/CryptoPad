#include "Python.h"
#include <openssl/aes.h>

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
	char* p = ctr_encrypted_counter;
	char* q = p+8;
	char *key, *buf, *pbuf;
	unsigned int key_len, buf_len, i;
	AES_KEY aes_key;

	if ( !PyArg_ParseTuple(args, "s#s#", &key, &key_len, &buf, &buf_len) ||
		AES_set_encrypt_key(key, key_len*8, &aes_key) < 0 )
		return Py_BuildValue("s", NULL);

	memset(ctr_counter_le, 0, 16);

	/* Lavora su una copia del buffer originale */
	pbuf = PyMem_Malloc(buf_len);
	memcpy(pbuf, buf, buf_len);
	buf = pbuf;

	for (i=0; i < buf_len/16; i++) {
#ifdef BYTE_ORDER_1234
		betole64(&ctr_counter_le);
#endif
		(*((unsigned long long*) ctr_counter_le))++;
		AES_ecb_encrypt(ctr_counter_le, ctr_encrypted_counter, &aes_key, 1);
		*((unsigned long long*) buf)++ ^= *((unsigned long long*) p);
		*((unsigned long long*) buf)++ ^= *((unsigned long long*) q);
	}

	if ((i = buf_len%16)) {
#ifdef BYTE_ORDER_1234
		betole64(&ctr_counter_le);
#endif
		(*((unsigned long long*) ctr_counter_le))++;
		AES_ecb_encrypt(ctr_counter_le, ctr_encrypted_counter, &aes_key, 1);
		while (i--)
			*buf++ ^= *p++;
	}

#if PY_MAJOR_VERSION > 2
	return Py_BuildValue("y#", pbuf, buf_len);
#else
	return Py_BuildValue("s#", pbuf, buf_len);
#endif
}


static PyMethodDef _libeay_methods[] =
{
 {"AES_ctr128_le_crypt", p_AES_ctr128_le_crypt, METH_VARARGS, "Encrypts with AES CTR-LE"},
 {NULL, NULL, 0, NULL}
};


#if PY_MAJOR_VERSION > 2
static struct PyModuleDef _libeay_module = {
   PyModuleDef_HEAD_INIT,
   "_libeay",   /* name of module */
   NULL, /* module documentation, may be NULL */
   -1,       /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   _libeay_methods
};

PyMODINIT_FUNC PyInit__libeay()
{
 return PyModule_Create(&_libeay_module);
}
#else
__declspec(dllexport)
void
init_libeay()
{
 Py_InitModule("_libeay", _libeay_methods);
}
#endif
