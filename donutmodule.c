/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

  Python C Extension by @byt3bl33d3r

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  * Redistributions of source code must retain the above copyright notice, this
    list of conditions and the following disclaimer.

  * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

  * Neither the name of the copyright holder nor the names of its
    contributors may be used to endorse or promote products derived from
    this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <Python.h>
#include "donut.h"


static PyObject *Donut_Create(PyObject *self, PyObject *args, PyObject *keywds) {
    int *arch = NULL;
    int *bypass = NULL;
    char *appdomain = NULL;
    char *file = NULL;
    char *runtime = NULL;
    char *url = NULL;
    char *cls = NULL;
    char *method = NULL;
    char *params = NULL;

    int err;

    static char *kwlist[] = {"file", "url", "arch", "bypass", "cls", "method", "params", "runtime", "appdomain", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|siisssss", kwlist, &file, &url, &arch, &bypass, &cls, &method, &params, &runtime, &appdomain)) {
        return NULL;
    }

    DONUT_CONFIG c;

    // zero initialize configuration
    memset(&c, 0, sizeof(c));

    // default type is position independent code for dual-mode (x86 + amd64)
    c.inst_type = DONUT_INSTANCE_PIC;
    c.arch      = DONUT_ARCH_X84;
    c.bypass    = DONUT_BYPASS_CONTINUE;  // continues loading even if disabling AMSI/WLDP fails

    // target cpu architecture
    if (arch != NULL) {
      c.arch = arch;
    }

    // bypass options
    if (bypass != NULL) {
      c.bypass = bypass;
    }

    // name of appdomain to use
    if (appdomain != NULL) {
      strncpy(c.domain, appdomain, DONUT_MAX_NAME - 1);
    }

    // assembly to use
    if (file != NULL) {
      strncpy(c.file, file, DONUT_MAX_NAME - 1);
    }

    //runtime version to use
    if (runtime != NULL) {
      strncpy(c.runtime, runtime, DONUT_MAX_NAME - 1);
    }

    // url of remote assembly
    if (url != NULL) {
        strncpy(c.url, url, DONUT_MAX_URL - 2);
        c.inst_type = DONUT_INSTANCE_URL;
    }

    // class
    if (cls != NULL) {
      strncpy(c.cls, cls, DONUT_MAX_NAME - 1);
    }

    // method or exported api symbol
    if (method != NULL) {
      strncpy(c.method, method, DONUT_MAX_NAME - 1);
    }

    // parameters to method/exported API
    if (params != NULL) {
      strncpy(c.param, params, sizeof(c.param) - 1);
    }

    err = DonutCreate(&c);

    /*
    if (!(c.pic_len > 0)) {
      return NULL;
    }
    */

    PyObject *shellcode = Py_BuildValue("y#", c.pic, c.pic_len);

    DonutDelete(&c);

    return shellcode;
}

// module's function table
static PyMethodDef Donut_FunctionsTable[] = {
    {
        "create", // name exposed to Python
        Donut_Create, // C wrapper function
        METH_VARARGS|METH_KEYWORDS,
        "Calls DonutCreate to generate shellcode for a .NET assembly" // documentation
    }, {
        NULL, NULL, 0, NULL
    }
};

// modules definition
static struct PyModuleDef Donut_Module = {
    PyModuleDef_HEAD_INIT,
    "donut",     // name of module exposed to Python
    "Donut Python C extension", // module documentation
    -1,
    Donut_FunctionsTable
};

PyMODINIT_FUNC PyInit_donut(void) {
    return PyModule_Create(&Donut_Module);
}
