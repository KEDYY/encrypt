#include "Python.h"
#include "sm4.h"
#ifndef uint8
#define uint8  unsigned char
#endif

static PyObject* sm4encrypt(PyObject* self, PyObject *args);
static PyObject* sm4decrypt(PyObject* self, PyObject *args);


static PyObject* sm4encrypt(PyObject* self, PyObject *args)
{
	const char *pkey;
	const char *pinput;
	int fixed_size =16;
	if (!PyArg_ParseTuple(args, "s#s#", &pkey, &fixed_size, &pinput, &fixed_size)){
		return NULL;
	}
	uint8 output[16]= {0};
	sm4_context sm4Key;
	sm4_setkey_enc(&sm4Key, (uint8*)pkey );
	sm4_crypt_ecb(&sm4Key, 1, 16, (uint8*)pinput, output );

	return Py_BuildValue("s#", output, fixed_size);
}

static PyObject* sm4decrypt(PyObject* self, PyObject *args)
{
	const char *pkey;
	const char *pinput;
	int fixed_size =16;
	if (!PyArg_ParseTuple(args, "s#s#", &pkey, &fixed_size, &pinput, &fixed_size)){
		return NULL;
	}
	uint8 output[16]= {0};
	sm4_context sm4Key;
	sm4_setkey_dec(&sm4Key, (uint8*)pkey );
	sm4_crypt_ecb(&sm4Key, 0, 16, (uint8*)pinput, output );

	return Py_BuildValue("s#", output, fixed_size);
}
static PyMethodDef pySM4Methods[]=
{
	{"encrypt", (PyCFunction)sm4encrypt, METH_VARARGS, "use C exec sm4 encrypt \n @param `key`: 16Byte SM4Key;\n @param  `data`: 16Byte Data;"},
	{"decrypt", (PyCFunction)sm4decrypt, METH_VARARGS, "use C exec sm4 decrypt \n @param `key`: 16Byte SM4Key;\n @param  `data`: 16Byte Data;"},
	{ NULL, NULL, 2, NULL }
    
}; 
PyMODINIT_FUNC initpySM4()
{
	PyObject* m;
	m = Py_InitModule("pySM4", pySM4Methods);
}
