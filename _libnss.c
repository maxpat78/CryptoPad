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
#include <pk11pub.h>
#include <seccomon.h>

#define PY_SSIZE_T_CLEAN size_t
#include <Python.h>

#ifdef BYTE_ORDER_1234
void betole64(uint64_t *x) {
*x = (*x & 0x00000000FFFFFFFF) << 32 | (*x & 0xFFFFFFFF00000000) >> 32;
*x = (*x & 0x0000FFFF0000FFFF) << 16 | (*x & 0xFFFF0000FFFF0000) >> 16;
*x = (*x & 0x00FF00FF00FF00FF) << 8  | (*x & 0xFF00FF00FF00FF00) >> 8;
}
#endif

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
		(*((uint64_t*) ctr_counter_le))++;
#else	
		(*((uint64_t*) ctr_counter_be))++;
		*((uint64_t*) ctr_counter_le) = *((uint64_t*) ctr_counter_be);
		betole64((uint64_t*)ctr_counter_le);
#endif
		PK11_CipherOp(ctxt, ctr_encrypted_counter, &olen, 16, ctr_counter_le, 16);

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
