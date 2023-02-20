/*
 *  Copyright (C) 2015-2023 maxpat78 <https://github.com/maxpat78>
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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <botan/ffi.h>

#define PY_SSIZE_T_CLEAN size_t
#include <Python.h>

#ifdef BYTE_ORDER_1234
void betole64(uint64_t *x) {
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
	char *key, *buf, *pbuf, *ppbuf, *mode;
	unsigned int key_len, buf_len, i;
	botan_block_cipher_t cipher;

	if ( !PyArg_ParseTuple(args, "s#s#", &key, &key_len, &buf, &buf_len))
		return Py_BuildValue("s", NULL);

	switch (key_len) {
		case 16:
			mode = "AES-128";
			break;
		case 24:
			mode = "AES-192";
			break;
		case 32:
			mode = "AES-256";
			break;
		default:
			return Py_BuildValue("s", NULL);
	}

	botan_block_cipher_init(&cipher, mode);
	botan_block_cipher_set_key(cipher, key, key_len);

#ifdef BYTE_ORDER_1234
	memset(ctr_counter_be, 0, 16);
#else
	memset(ctr_counter_le, 0, 16);
#endif
	
	/* Lavora su una copia del buffer originale */
	ppbuf = pbuf = PyMem_Malloc(buf_len);

	for (i=0; i < buf_len/16; i++) {
#ifndef BYTE_ORDER_1234
		(*((uint64_t*) ctr_counter_le))++;
#else	
		(*((uint64_t*) ctr_counter_be))++;
		*((uint64_t*) ctr_counter_le) = *((uint64_t*) ctr_counter_be);
		betole64((uint64_t*)ctr_counter_le);
#endif
		botan_block_cipher_encrypt_blocks(cipher, ctr_counter_le, ctr_encrypted_counter, 1);

		*((uint64_t*) pbuf) = *((uint64_t*) buf) ^ *((uint64_t*) p);
		pbuf+=sizeof(uint64_t);
		buf+=sizeof(uint64_t);

		*((uint64_t*) pbuf) = *((uint64_t*) buf) ^ *((uint64_t*) q);
		pbuf+=sizeof(uint64_t);
		buf+=sizeof(uint64_t);
	}

	if ((i = buf_len%16)) {
#ifndef BYTE_ORDER_1234
		(*((uint64_t*) ctr_counter_le))++;
#else	
		(*((uint64_t*) ctr_counter_be))++;
		*((uint64_t*) ctr_counter_le) = *((uint64_t*) ctr_counter_be);
		betole64((uint64_t*)ctr_counter_le);
#endif
		botan_block_cipher_encrypt_blocks(cipher, ctr_counter_le, ctr_encrypted_counter, 1);
		while (i--)
			*pbuf++ = *buf++ ^ *p++;
	}

#if PY_MAJOR_VERSION > 2
	return Py_BuildValue("y#", ppbuf, buf_len);
#else
	return Py_BuildValue("s#", ppbuf, buf_len);
#endif
}


static PyMethodDef _libbotan_methods[] =
{
 {"AES_ctr128_le_crypt", p_AES_ctr128_le_crypt, METH_VARARGS, "Encrypts with AES CTR-LE (via Botan)"},
 {NULL, NULL, 0, NULL}
};


#if PY_MAJOR_VERSION > 2
static struct PyModuleDef _libbotan_module = {
   PyModuleDef_HEAD_INIT,
   "_libbotan",   /* name of module */
   NULL, /* module documentation, may be NULL */
   -1,       /* size of per-interpreter state of the module,
                or -1 if the module keeps state in global variables. */
   _libbotan_methods
};

PyMODINIT_FUNC PyInit__libbotan()
{
 return PyModule_Create(&_libbotan_module);
}
#else
__declspec(dllexport)
void
init_libbotan()
{
 Py_InitModule("_libbotan", _libbotan_methods);
}
#endif
