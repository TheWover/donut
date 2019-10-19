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

// initialize interface with methods/properties
static HRESULT Host_New(PDONUT_INSTANCE inst, IHost *host) {
    HRESULT hr;
    WCHAR   buf[DONUT_MAX_NAME+1];
    
    // IUnknown interface
    host->lpVtbl->QueryInterface     = ADR(LPVOID, Host_QueryInterface);
    host->lpVtbl->AddRef             = ADR(LPVOID, Host_AddRef);
    host->lpVtbl->Release            = ADR(LPVOID, Host_Release);
    
    // IDispatch interface
    host->lpVtbl->GetTypeInfoCount   = ADR(LPVOID, Host_GetTypeInfoCount);
    host->lpVtbl->GetTypeInfo        = ADR(LPVOID, Host_GetTypeInfo);
    host->lpVtbl->GetIDsOfNames      = ADR(LPVOID, Host_GetIDsOfNames);
    host->lpVtbl->Invoke             = ADR(LPVOID, Host_Invoke);
    
    // IHost interface
    host->lpVtbl->get_Name           = ADR(LPVOID, Host_get_Name);
    host->lpVtbl->get_Application    = ADR(LPVOID, Host_get_Application);
    host->lpVtbl->get_FullName       = ADR(LPVOID, Host_get_FullName);
    host->lpVtbl->get_Path           = ADR(LPVOID, Host_get_Path);
    host->lpVtbl->get_Interactive    = ADR(LPVOID, Host_get_Interactive);
    host->lpVtbl->put_Interactive    = ADR(LPVOID, Host_put_Interactive);
    host->lpVtbl->Quit               = ADR(LPVOID, Host_Quit);
    host->lpVtbl->get_ScriptName     = ADR(LPVOID, Host_get_ScriptName);
    host->lpVtbl->get_ScriptFullName = ADR(LPVOID, Host_get_ScriptFullName);
    host->lpVtbl->get_Arguments      = ADR(LPVOID, Host_get_Arguments);
    host->lpVtbl->get_Version        = ADR(LPVOID, Host_get_Version);
    host->lpVtbl->get_BuildVersion   = ADR(LPVOID, Host_get_BuildVersion);
    host->lpVtbl->get_Timeout        = ADR(LPVOID, Host_get_Timeout);
    host->lpVtbl->put_Timeout        = ADR(LPVOID, Host_put_Timeout);
    host->lpVtbl->CreateObject       = ADR(LPVOID, Host_CreateObject);
    host->lpVtbl->Echo               = ADR(LPVOID, Host_Echo);
    host->lpVtbl->GetObject          = ADR(LPVOID, Host_GetObject);
    host->lpVtbl->DisconnectObject   = ADR(LPVOID, Host_DisconnectObject);
    host->lpVtbl->Sleep              = ADR(LPVOID, Host_Sleep);
    host->lpVtbl->ConnectObject      = ADR(LPVOID, Host_ConnectObject);
    host->lpVtbl->get_StdIn          = ADR(LPVOID, Host_get_StdIn);
    host->lpVtbl->get_StdOut         = ADR(LPVOID, Host_get_StdOut);
    host->lpVtbl->get_StdErr         = ADR(LPVOID, Host_get_StdErr);
    
    host->m_cRef                     = 0;
    host->inst                       = inst;
    
    DPRINT("LoadTypeLib(\"%s\")", inst->wscript_exe);
    ansi2unicode(inst, inst->wscript_exe, buf);
    hr = inst->api.LoadTypeLib(buf, &host->lpTypeLib);
    
    if(hr == S_OK) {
      DPRINT("ITypeLib::GetTypeInfoOfGuid");
      
      hr = host->lpTypeLib->lpVtbl->GetTypeInfoOfGuid(
        host->lpTypeLib, &inst->xIID_IHost, &host->lpTypeInfo);
    }
    DPRINT("HRESULT : %08lx", hr);
    return hr;
}

// Queries a COM object for a pointer to one of its interface.
static HRESULT WINAPI Host_QueryInterface(IHost *iface, REFIID riid, void **ppv) {
    DPRINT("WScript::QueryInterface");

    if(ppv == NULL) return E_POINTER;
    
    // we implement the following interfaces
    if(IsEqualIID(&iface->inst->xIID_IUnknown,  riid)  ||
       IsEqualIID(&iface->inst->xIID_IDispatch, riid) ||
       IsEqualIID(&iface->inst->xIID_IHost,     riid)) 
    {
        *ppv = iface;
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

// Increments the reference count for an interface pointer to a COM object.
static ULONG WINAPI Host_AddRef(IHost *iface) {
    DPRINT("WScript::AddRef");
    
    _InterlockedIncrement(&iface->m_cRef);
    return iface->m_cRef;
}

// Decrements the reference count for an interface on a COM object.
static ULONG WINAPI Host_Release(IHost *iface) {
    DPRINT("WScript::Release");
    
    ULONG ref = _InterlockedDecrement(&iface->m_cRef);
    return ref;
}

// Retrieves the number of type information interfaces that an object provides (either 0 or 1).
static HRESULT WINAPI Host_GetTypeInfoCount(IHost *iface, UINT *pctinfo) {
    DPRINT("WScript::GetTypeInfoCount");
    
    if(pctinfo == NULL) return E_POINTER;
    
    *pctinfo = 1;
    return S_OK;
}

// Retrieves the type information for an object, which can then be used to get the type information for an interface.
static HRESULT WINAPI Host_GetTypeInfo(IHost *iface, UINT iTInfo, LCID lcid, ITypeInfo **ppTInfo) {
    DPRINT("WScript::GetTypeInfo");
    
    if(ppTInfo == NULL) return E_POINTER;
    
    iface->lpTypeInfo->lpVtbl->AddRef(iface->lpTypeInfo);
    *ppTInfo = iface->lpTypeInfo;
    
    return S_OK;
}

// Maps a single member and an optional set of argument names to a corresponding set of integer DISPIDs, 
// which can be used on subsequent calls to Invoke.
static HRESULT WINAPI Host_GetIDsOfNames(IHost *iface, REFIID riid, 
    LPOLESTR *rgszNames, UINT cNames, LCID lcid, DISPID *rgDispId) {
    DPRINT("WScript::GetIDsOfNames");

    return iface->lpTypeInfo->lpVtbl->GetIDsOfNames(iface->lpTypeInfo, rgszNames, cNames, rgDispId);
}

// Provides access to properties and methods exposed by an object. 
// The dispatch function DispInvoke provides a standard implementation of Invoke.
static HRESULT WINAPI Host_Invoke(
  IHost *iface, DISPID dispIdMember, REFIID riid,
  LCID lcid, WORD wFlags, DISPPARAMS *pDispParams, VARIANT *pVarResult,
  EXCEPINFO *pExcepInfo, UINT *puArgErr) {
          
    DPRINT("WScript::Invoke");

    HRESULT hr = iface->lpTypeInfo->lpVtbl->Invoke(
      iface->lpTypeInfo, iface, dispIdMember, wFlags, pDispParams,
      pVarResult, pExcepInfo, puArgErr);
            
    DPRINT("HRESULT : %08lx", hr);
    
    return hr;
}

// Returns the name of the WScript object (the host executable file).
static HRESULT WINAPI Host_get_Name(IHost *iface, BSTR *out_Name) {
    DPRINT("WScript::Name");
    
    return S_OK;
}

static HRESULT WINAPI Host_get_Application(IHost *iface, IDispatch **out_Dispatch) {
    DPRINT("WScript::Application");
    
    return E_NOTIMPL;
}

// Returns the fully qualified path of the host executable (CScript.exe or WScript.exe).
static HRESULT WINAPI Host_get_FullName(IHost *iface, BSTR *out_Path) {
    DPRINT("WScript::FullName");
    
    return E_NOTIMPL;
}

static HRESULT WINAPI Host_get_Path(IHost *iface, BSTR *out_Path) {
    DPRINT("WScript::Path");
    
    return E_NOTIMPL;
}

// Gets the script mode, or identifies the script mode.
static HRESULT WINAPI Host_get_Interactive(IHost *iface, VARIANT_BOOL *out_Interactive) {
    DPRINT("WScript::get_Interactive");
    
    return E_NOTIMPL;
}

// Sets the script mode, or identifies the script mode.
static HRESULT WINAPI Host_put_Interactive(IHost *iface, VARIANT_BOOL v) {
    DPRINT("WScript::put_Interactive");
    
    return E_NOTIMPL;
}

// Forces script execution to stop at any time.
static HRESULT WINAPI Host_Quit(IHost *iface, int ExitCode) {
    DPRINT("WScript::Quit(%i)", ExitCode);
    
    // if you know of a better way to do this..let me know.
    iface->lpEngine->lpVtbl->InterruptScriptThread(iface->lpEngine, SCRIPTTHREADID_CURRENT, NULL, 0);
    
    return S_OK;
}

// Returns the file name of the currently running script.
static HRESULT WINAPI Host_get_ScriptName(IHost *iface, BSTR *out_ScriptName) {
    DPRINT("WScript::ScriptName");
    
    return E_NOTIMPL;
}

// Returns the full path of the currently running script.
static HRESULT WINAPI Host_get_ScriptFullName(IHost *iface, BSTR *out_ScriptFullName) {
    DPRINT("WScript::ScriptFullName");
    
    return E_NOTIMPL;
}

// Returns the WshArguments object (a collection of arguments).
static HRESULT WINAPI Host_get_Arguments(
    IHost *iface, void **out_Arguments) { // IArguments2
      DPRINT("WScript::Arguments");
      
      return E_NOTIMPL;
}

static HRESULT WINAPI Host_get_Version(IHost *iface, BSTR *out_Version) {
    DPRINT("WScript::Version");
    
    return E_NOTIMPL;
}

// Returns the Windows Script Host build version number.
static HRESULT WINAPI Host_get_BuildVersion(IHost *iface, int *out_Build) {
    DPRINT("WScript::BuildVersion");
    
    return E_NOTIMPL;
}

static HRESULT WINAPI Host_get_Timeout(IHost *iface, LONG *out_Timeout) {
    DPRINT("WScript::get_Timeout");
    
    return E_NOTIMPL;
}

static HRESULT WINAPI Host_put_Timeout(IHost *iface, LONG v) {
    DPRINT("WScript::put_Timeout");
    
    return E_NOTIMPL;
}

// Connects the object's event sources to functions with a given prefix.
static HRESULT WINAPI Host_CreateObject(IHost *iface, BSTR ProgID, BSTR Prefix,
        IDispatch **out_Dispatch) {
    DPRINT("WScript::CreateObject");
    
    return E_NOTIMPL;
}

// Outputs text to either a message box or the command console window.
static HRESULT WINAPI Host_Echo(
    IHost *iface, SAFEARRAY *args) {
      DPRINT("WScript::Echo");
      
      return E_NOTIMPL;
}

// Retrieves an existing object with the specified ProgID, or creates a new one from a file.
static HRESULT WINAPI Host_GetObject(
    IHost *iface, BSTR Pathname, BSTR ProgID,
    BSTR Prefix, IDispatch **out_Dispatch) {
      DPRINT("WScript::GetObject");
      
      return E_NOTIMPL;
}

// Disconnects a connected object's event sources.
static HRESULT WINAPI Host_DisconnectObject(
    IHost *iface, IDispatch *Object) {
      DPRINT("WScript::DisconnectObject");
      
      return E_NOTIMPL;
}

// Suspends script execution for a specified length of time, then continues execution.
static HRESULT WINAPI Host_Sleep(
  IHost *iface, LONG Time) {
    
    DPRINT("WScript::Sleep");
    iface->inst->api.Sleep((DWORD)Time);
    
    return S_OK;
}

// Connects the object's event sources to functions with a given prefix.
static HRESULT WINAPI Host_ConnectObject(
    IHost *iface, IDispatch *Object, BSTR Prefix) {
      DPRINT("WScript::ConnectObject");
      
      return E_NOTIMPL;
}

// Exposes the read-only input stream for the current script.
static HRESULT WINAPI Host_get_StdIn(
    IHost *iface, void **ppts) { // ppts is ITextStream 
      DPRINT("WScript::StdIn");
      
      return E_NOTIMPL;
}

// Exposes the write-only output stream for the current script.
static HRESULT WINAPI Host_get_StdOut(
    IHost *iface, void **ppts) { // ppts is ITextStream
      DPRINT("WScript::StdOut");
      
      return E_NOTIMPL;
}

// Exposes the write-only error output stream for the current script.
static HRESULT WINAPI Host_get_StdErr(
    IHost *iface, void **ppts) { // ppts is ITextStream 
      DPRINT("WScript::StdErr");
      
      return E_NOTIMPL;
}
