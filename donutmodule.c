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

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "donut.h"

static PyObject *Donut_Create(PyObject *self, PyObject *args, PyObject *keywds) {
    char *input = NULL;       // input file to execute in-memory
    
    int arch      = 0;     // target CPU architecture or mode
    int bypass    = 0;     // AMSI/WDLP bypassing behavior
    int headers   = 0;     // Preserve PE headers behavior
    int compress  = 0;     // compress input file
    int entropy   = 0;     // whether to randomize API hashes and use encryption
    int format    = 0;     // output format
    int exit_opt  = 0;     // exit process or exit thread
    int thread    = 0;     // run unmanaged entrypoint as a thread
    char *oep     = NULL;  // creates new thread for loader and continues execution at specified address provided in hexadecimal format
    
    char *output  = NULL;     // name of loader stored on disk
    
    char *runtime = NULL;     // runtime version
    char *domain  = NULL;     // app domain name to use
    char *cls     = NULL;     // class name 
    char *method  = NULL;     // method name
    
    char *params  = NULL;     // parameters for method
    int  unicode  = 0;        // param is converted to unicode before being passed to unmanaged DLL function

    char *decoy   = NULL;     // path of decoy module
    
    char *server  = NULL;     // HTTP server to download module from
    char *modname = NULL;     // name of module stored on HTTP server
    
    static char *kwlist[] = {
      "file", "arch", "bypass", "headers", "compress", "entropy", 
      "format", "exit_opt", "thread", "oep", "output", 
      "runtime", "appdomain", "cls", "method", "params", 
      "unicode", "server", "url", "modname", NULL};
      
    if (!PyArg_ParseTupleAndKeywords(
      args, keywds, "s|iiiiiiiisssssssissss", kwlist, &input, &arch, 
      &bypass, &headers, &compress, &entropy, &format, &exit_opt, &thread, 
      &oep, &output, &runtime, &domain, &cls, &method, &params, &unicode,
      &decoy, &server, &server, &modname)) 
    {
        return NULL;
    }

    DONUT_CONFIG c;

    // zero initialize configuration
    memset(&c, 0, sizeof(c));
    
    // default settings
    c.inst_type = DONUT_INSTANCE_EMBED;    // file is embedded
    c.arch      = DONUT_ARCH_X84;          // dual-mode (x86+amd64)
    c.bypass    = DONUT_BYPASS_CONTINUE;   // continues loading even if disabling AMSI/WLDP fails
    c.headers   = DONUT_HEADERS_OVERWRITE;// overwrite PE header
    c.format    = DONUT_FORMAT_BINARY;     // default output format
    c.compress  = DONUT_COMPRESS_NONE;     // compression is disabled by default
    c.entropy   = DONUT_ENTROPY_DEFAULT;   // enable random names + symmetric encryption by default
    c.exit_opt  = DONUT_OPT_EXIT_THREAD;   // default behaviour is to exit the thread
    c.unicode   = 0;                       // command line will not be converted to unicode for unmanaged DLL function

    // input file
    if(input != NULL) {
      strncpy(c.input, input, DONUT_MAX_NAME - 1);
    }
    
    // target cpu architecture
    if(arch != 0) {
      c.arch = arch;
    }
    // bypass options
    if(bypass != 0) {
      c.bypass = bypass;
    }
    // headers options
    if(headers != 0) {
      c.headers = headers;
    }
    // class of .NET assembly
    if(cls != NULL) {
      strncpy(c.cls, cls, DONUT_MAX_NAME - 1);
    }
    // name of domain to use for .NET assembly
    if(domain != NULL) {
      strncpy(c.domain, domain, DONUT_MAX_NAME - 1);
    }
    // encryption options
    if(entropy != 0) {
      c.entropy = entropy;
    }
    // output format
    if(format != 0) {
      c.format = format;
    }
    // method of .NET assembly
    if(method != NULL) {
      strncpy(c.method, method, DONUT_MAX_NAME - 1);
    }
    // module name
    if(modname != NULL) {
      strncpy(c.modname, modname, DONUT_MAX_NAME - 1);
    }
    // output file for loader
    if(output != NULL) {
      strncpy(c.output, output, DONUT_MAX_NAME - 1);
    }
    // parameters to method, DLL function or command line for unmanaged EXE
    if(params != NULL) {
      strncpy(c.args, params, DONUT_MAX_NAME - 1);
    }
    // path of decoy file
    if(decoy != NULL) {
      strncpy(c.decoy, decoy, 2048);
    }
    // runtime version to use for .NET DLL / EXE
    if(runtime != NULL) {
      strncpy(c.runtime, runtime, DONUT_MAX_NAME - 1);
    }
    // run entrypoint of unmanaged EXE as a thread
    if(thread != 0) {
      c.thread = 1;
    }
    // server
    if(server != NULL) {
      strncpy(c.server, server, DONUT_MAX_NAME - 2);
      c.inst_type = DONUT_INSTANCE_HTTP;
    }
    // convert param to unicode? only applies to unmanaged DLL function
    if(unicode != 0) {
      c.unicode = 1;
    }
    // call RtlExitUserProcess to terminate host process
    if(exit_opt != 0) {
      c.exit_opt = exit_opt;
    }
    // fork a new thread and execute address of original entry point
    if(oep != NULL) {
      c.oep = strtoull(oep, NULL, 16);
    }
    // pack/compress input file
    if(compress != 0) {
      c.compress = compress;
    }

    int err = DonutCreate(&c);

    if(err != 0) {
        PyErr_SetString(PyExc_RuntimeError, DonutError(err));
        DonutDelete(&c);
        return NULL;
    }

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
    }, 
    
    {NULL, NULL, 0, NULL}
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
