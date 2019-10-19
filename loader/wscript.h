/**
  BSD 3-Clause License

  Copyright (c) 2019, TheWover, Odzhan. All rights reserved.

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

#ifndef WSCRIPT_H
#define WSCRIPT_H

#include "../include/donut.h"

typedef struct _IHost IHost;

typedef struct _IHostVtbl {
    BEGIN_INTERFACE
    
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(
      IHost        *This, 
      REFIID       riid, 
      void         **ppvObject);

    ULONG (STDMETHODCALLTYPE *AddRef)(IHost *This);

    ULONG (STDMETHODCALLTYPE *Release)(IHost *This);
          
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(
      IHost        *This, 
      UINT         *pctinfo);

    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(
      IHost        *This, 
      UINT         iTInfo, 
      LCID         lcid, 
      ITypeInfo    **ppTInfo);

    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(
      IHost        *This, 
      REFIID       riid, 
      LPOLESTR     *rgszNames,
      UINT         cNames, 
      LCID         lcid, 
      DISPID       *rgDispId);

    HRESULT (STDMETHODCALLTYPE *Invoke)(
      IHost        *This, 
      DISPID       dispIdMember, 
      REFIID       riid,
      LCID         lcid, 
      WORD         wFlags, 
      DISPPARAMS   *pDispParams, 
      VARIANT      *pVarResult,
      EXCEPINFO    *pExcepInfo, 
      UINT         *puArgErr);
    
    HRESULT (STDMETHODCALLTYPE *get_Name)(
      IHost        *This, 
      BSTR         *out_Name);

    HRESULT (STDMETHODCALLTYPE *get_Application)(
      IHost        *This, 
      IDispatch    **out_Dispatch);

    HRESULT (STDMETHODCALLTYPE *get_FullName)(
      IHost        *This, 
      BSTR         *out_Path);

    HRESULT (STDMETHODCALLTYPE *get_Path)(
      IHost        *This, 
      BSTR         *out_Path);

    HRESULT (STDMETHODCALLTYPE *get_Interactive)(
      IHost        *This, 
      VARIANT_BOOL *out_Interactive);

    HRESULT (STDMETHODCALLTYPE *put_Interactive)(
      IHost        *This, 
      VARIANT_BOOL v);

    HRESULT (STDMETHODCALLTYPE *Quit)(
      IHost        *This, 
      int          ExitCode);

    HRESULT (STDMETHODCALLTYPE *get_ScriptName)(
      IHost        *This, 
      BSTR         *out_ScriptName);

    HRESULT (STDMETHODCALLTYPE *get_ScriptFullName)(
      IHost        *This, 
      BSTR         *out_ScriptFullName);

    HRESULT (STDMETHODCALLTYPE *get_Arguments)(
      IHost        *This, 
      void         **out_Arguments);

    HRESULT (STDMETHODCALLTYPE *get_Version)(
      IHost        *This, 
      BSTR         *out_Version);

    HRESULT (STDMETHODCALLTYPE *get_BuildVersion)(
      IHost        *This, 
      int          *out_Build);

    HRESULT (STDMETHODCALLTYPE *get_Timeout)(
      IHost        *This, 
      LONG         *out_Timeout);

    HRESULT (STDMETHODCALLTYPE *put_Timeout)(
      IHost        *This, 
      LONG         v);

    HRESULT (STDMETHODCALLTYPE *CreateObject)(
      IHost        *This, 
      BSTR         ProgID, 
      BSTR         Prefix, 
      IDispatch    **out_Dispatch);

    HRESULT (STDMETHODCALLTYPE *Echo)(
      IHost        *This, 
      SAFEARRAY    *args);

    HRESULT (STDMETHODCALLTYPE *GetObject)(
      IHost        *This, 
      BSTR         Pathname, 
      BSTR         ProgID, 
      BSTR         Prefix, 
      IDispatch    **out_Dispatch);

    HRESULT (STDMETHODCALLTYPE *DisconnectObject)(
      IHost        *This, 
      IDispatch    *Object);

    HRESULT (STDMETHODCALLTYPE *Sleep)(
      IHost        *This, 
      LONG         Time);

    HRESULT (STDMETHODCALLTYPE *ConnectObject)(
      IHost        *This, 
      IDispatch    *Object, 
      BSTR         Prefix);

    HRESULT (STDMETHODCALLTYPE *get_StdIn)(
      IHost        *This, 
      void         **ppts);

    HRESULT (STDMETHODCALLTYPE *get_StdOut)(
      IHost        *This, 
      void         **ppts);

    HRESULT (STDMETHODCALLTYPE *get_StdErr)(
      IHost        *This, 
      void         **ppts);
      
    END_INTERFACE
} IHostVtbl;

typedef struct _IHost {
    IHostVtbl       *lpVtbl;     // virtual function table
    ITypeLib        *lpTypeLib;  // type library
    ITypeInfo       *lpTypeInfo; // type information for WScript properties/methods
    IActiveScript   *lpEngine;   // IActiveScript engine from main thread
    ULONG           m_cRef;      // reference count
    PDONUT_INSTANCE inst;
} IHost;

static HRESULT Host_New(PDONUT_INSTANCE inst, IHost *host);

// Queries a COM object for a pointer to one of its interface.
static STDMETHODIMP Host_QueryInterface(IHost *This, REFIID riid, void **ppv);

// Increments the reference count for an interface pointer to a COM object.
static STDMETHODIMP_(ULONG) Host_AddRef(IHost *This);

// Decrements the reference count for an interface on a COM object.
static STDMETHODIMP_(ULONG) Host_Release(IHost *This);

// Retrieves the number of type information interfaces that an object provides (either 0 or 1).
static STDMETHODIMP Host_GetTypeInfoCount(IHost *This, UINT *pctinfo);

// Retrieves the type information for an object, which can then be used to get the type information for an interface.
static STDMETHODIMP Host_GetTypeInfo(IHost *This, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo);

// Maps a single member and an optional set of argument names to a corresponding set of integer DISPIDs, 
// which can be used on subsequent calls to Invoke.
static STDMETHODIMP Host_GetIDsOfNames(
  IHost *This, REFIID riid, LPOLESTR *rgszNames,
  UINT cNames, LCID lcid, DISPID *rgDispId);

// Provides access to properties and methods exposed by an object. 
// The dispatch function DispInvoke provides a standard implementation of Invoke.
static STDMETHODIMP Host_Invoke(
  IHost *This, DISPID dispIdMember, REFIID riid,
  LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult,
  EXCEPINFO *pExcepInfo, UINT *puArgErr);

// Returns the name of the WScript object (the host executable file).
static STDMETHODIMP Host_get_Name(IHost *This, BSTR *out_Name);

static STDMETHODIMP Host_get_Application(IHost *This, IDispatch **out_Dispatch);

// Returns the fully qualified path of the host executable (CScript.exe or WScript.exe).
static STDMETHODIMP Host_get_FullName(IHost *This, BSTR *out_Path);

static STDMETHODIMP Host_get_Path(IHost *This, BSTR *out_Path);

// Gets the script mode, or identifies the script mode.
static STDMETHODIMP Host_get_Interactive(IHost *This, VARIANT_BOOL *out_Interactive);

// Sets the script mode, or identifies the script mode.
static STDMETHODIMP Host_put_Interactive(IHost *This, VARIANT_BOOL v);

// Forces script execution to stop at any time.
static STDMETHODIMP Host_Quit(IHost *This, int ExitCode);

// Returns the file name of the currently running script.
static STDMETHODIMP Host_get_ScriptName(IHost *This, BSTR *out_ScriptName);

// Returns the full path of the currently running script.
static STDMETHODIMP Host_get_ScriptFullName(IHost *This, BSTR *out_ScriptFullName);

// Returns the WshArguments object (a collection of arguments).
static STDMETHODIMP Host_get_Arguments(IHost *This, void **out_Arguments);

static STDMETHODIMP Host_get_Version(IHost *This, BSTR *out_Version);

// Returns the Windows Script Host build version number.
static STDMETHODIMP Host_get_BuildVersion(IHost *This, int *out_Build);

static STDMETHODIMP Host_get_Timeout(IHost *This, LONG *out_Timeout);

static STDMETHODIMP Host_put_Timeout(IHost *This, LONG v);

// Connects the object's event sources to functions with a given prefix.
static STDMETHODIMP Host_CreateObject(IHost *This, BSTR ProgID, BSTR Prefix, IDispatch **out_Dispatch);

// Outputs text to either a message box or the command console window.
static STDMETHODIMP Host_Echo(IHost *This, SAFEARRAY *args);

// Retrieves an existing object with the specified ProgID, or creates a new one from a file.
static STDMETHODIMP Host_GetObject(IHost *This, BSTR Pathname, BSTR ProgID, BSTR Prefix, IDispatch **out_Dispatch);

// Disconnects a connected object's event sources.
static STDMETHODIMP Host_DisconnectObject(IHost *This, IDispatch *Object);

// Suspends script execution for a specified length of time, then continues execution.
static STDMETHODIMP Host_Sleep(IHost *This, LONG Time);

// Connects the object's event sources to functions with a given prefix.
static STDMETHODIMP Host_ConnectObject(IHost *This, IDispatch *Object, BSTR Prefix);

// Exposes the read-only input stream for the current script.
static STDMETHODIMP Host_get_StdIn(IHost *This, void **ppts);

// Exposes the write-only output stream for the current script.
static STDMETHODIMP Host_get_StdOut(IHost *This, void **ppts);

// Exposes the write-only error output stream for the current script.
static STDMETHODIMP Host_get_StdErr(IHost *This, void **ppts);

#endif
