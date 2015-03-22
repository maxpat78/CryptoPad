#include "Python.h"
#include <openssl/aes.h>

/*
Nel modo CTR il cifrato risulta dallo XOR tra ciascun blocco di testo in chiaro
e un contatore cifrato in modo ECB realizzato, preferibilmente, mediante unione
di n bit casuali con n bit di contatore.

I protocolli AE-1 e AE-2 di WinZip richiedono che il contatore sia un numero a
128 bit codificato in Little Endian diversamente dalle maggiori implementazioni
in Big Endian; inoltre il contatore parte da 1 senza alcun contenuto casuale.

NOTA: la versione in Python con ctypes è circa 72 volte più lenta!
*/
static PyObject *
p_AES_ctr128_le_crypt(self, args)
PyObject *self, *args;
{
	char *s, *key, *out_buf;
	unsigned int s_len, key_len, i, j;
	char ctr_counter_le[16], *ctr_encrypted_counter;
	unsigned long long *p;
	AES_KEY aes_key;

	if (!PyArg_ParseTuple(args, "s#s#", &key, &key_len, &s, &s_len)) return 0;

	if (AES_set_encrypt_key(key, key_len*8, &aes_key) < 0)
		return Py_BuildValue("z", 0);

	memset(ctr_counter_le, 0, 16);
	ctr_encrypted_counter = out_buf = malloc(s_len);
	p = (unsigned long long*) s;

	for (i=0; i < s_len/16; i++) {
		(*((unsigned int*) ctr_counter_le))++;
		AES_ecb_encrypt(ctr_counter_le, ctr_encrypted_counter, &aes_key, 1);
		*((unsigned long long*) ctr_encrypted_counter)++ ^= *p++;
		*((unsigned long long*) ctr_encrypted_counter)++ ^= *p++;
	}

	j = s_len%16;
	if (j) {
		(*((unsigned int*) ctr_counter_le))++;
		AES_ecb_encrypt(ctr_counter_le, ctr_encrypted_counter, &aes_key, 1);
		for (i=0; i < j; i++) {
			ctr_encrypted_counter[i] ^= ((char*)p)[i];
		}
	}

	return Py_BuildValue("s#", out_buf, s_len);
}


static PyMethodDef _libeay_methods[] =
{
 {"AES_ctr128_le_crypt", p_AES_ctr128_le_crypt, METH_VARARGS, "AES_ctr128_le_crypt(key, s)"},
 {NULL, NULL, 0, NULL}
};

__declspec(dllexport)
void
init_libeay()
{
 Py_InitModule("_libeay", _libeay_methods);
}
