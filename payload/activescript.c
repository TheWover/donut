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

#include "activescript.h"
#include "../include/donut.h"

// return pointer to code in memory
extern char *get_pc(void);

// PC-relative addressing. Similar to RVA2VA except using functions in payload
#define ADR(type, addr) (type)(get_pc() - ((ULONG_PTR)&get_pc - (ULONG_PTR)addr))

// initialize virtual function table
static VOID ActiveScript_New(IActiveScriptSite *site) {
    // Initialize IUnknown
    site->lpVtbl->QueryInterface      = ADR(LPVOID, ActiveScript_QueryInterface);
    site->lpVtbl->AddRef              = ADR(LPVOID, ActiveScript_AddRef);
    site->lpVtbl->Release             = ADR(LPVOID, ActiveScript_Release);
    
    // Initialize IActiveScriptSite
    site->lpVtbl->GetLCID             = ADR(LPVOID, ActiveScript_GetLCID);
    site->lpVtbl->GetItemInfo         = ADR(LPVOID, ActiveScript_GetItemInfo);
    site->lpVtbl->GetDocVersionString = ADR(LPVOID, ActiveScript_GetDocVersionString);
    site->lpVtbl->OnScriptTerminate   = ADR(LPVOID, ActiveScript_OnScriptTerminate);
    site->lpVtbl->OnStateChange       = ADR(LPVOID, ActiveScript_OnStateChange);
    site->lpVtbl->OnScriptError       = ADR(LPVOID, ActiveScript_OnScriptError);
    site->lpVtbl->OnEnterScript       = ADR(LPVOID, ActiveScript_OnEnterScript);
    site->lpVtbl->OnLeaveScript       = ADR(LPVOID, ActiveScript_OnLeaveScript);
}

static STDMETHODIMP ActiveScript_QueryInterface(IActiveScriptSite *this, REFIID riid, void **ppv) {
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
    
    DPRINT("IActiveScriptSite::QueryInterface"); 
    
    if(ppv == NULL) return E_POINTER;
    
    // we implement the following interfaces
    if(IsEqualIID(&mas->inst->xIID_IUnknown,          riid) || 
       IsEqualIID(&mas->inst->xIID_IActiveScriptSite, riid)) 
    {
      *ppv = (LPVOID)this;
      ActiveScript_AddRef(this);
      return S_OK;
    } 
    *ppv = NULL;
    return E_NOINTERFACE;
}

static STDMETHODIMP_(ULONG) ActiveScript_AddRef(IActiveScriptSite *this) {
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
  
    _InterlockedIncrement(&mas->m_cRef);
  
    DPRINT("IActiveScriptSite::AddRef : m_cRef : %i\n", mas->m_cRef);
  
    return mas->m_cRef;
}

static STDMETHODIMP_(ULONG) ActiveScript_Release(IActiveScriptSite *this) {
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
    
    ULONG ulRefCount = _InterlockedDecrement(&mas->m_cRef);

    DPRINT("IActiveScriptSite::Release : m_cRef : %i\n", ulRefCount);    
    return ulRefCount;
}

static STDMETHODIMP ActiveScript_GetItemInfo(IActiveScriptSite *this, 
  LPCOLESTR objectName, DWORD dwReturnMask, 
  IUnknown **objPtr, ITypeInfo **ppti) 
{
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
      
    DPRINT("IActiveScriptSite::GetItemInfo");   
    
    if(lstrcmp(objectName, L"WSH") && lstrcmp(objectName, L"WScript"))
        return E_FAIL;

    if(ppti != NULL) {
      printf("Returning type info");
      *ppti = host_ti;
    }
    if(objPtr != NULL) {
      printf("Returning i unknown");
      *objPtr = (IUnknown*)&mas->host_obj;
    }
    if(dwReturnMask & SCRIPTINFO_ITYPEINFO) {
        printf("Type info");
        
        host_ti->lpVtbl->AddRef(host_ti);
        *ppti = host_ti;
    }

    if(dwReturnMask & SCRIPTINFO_IUNKNOWN) {
      printf("IUnknown");
      
      mas->host_obj.lpVtbl->AddRef(&mas->host_obj);
      *objPtr = (IUnknown*)&mas->host_obj;
    }

    return S_OK;
}

static STDMETHODIMP ActiveScript_OnScriptError(IActiveScriptSite *this, 
  IActiveScriptError *scriptError) 
{
    DPRINT("IActiveScriptSite::OnScriptError");
    BSTR line;
    
    EXCEPINFO ei;
		ZeroMemory(&ei, sizeof(EXCEPINFO));
		HRESULT hr = scriptError->lpVtbl->GetExceptionInfo(scriptError, &ei);
    printf("HRESULT : %08lx\n", hr);
    
		DWORD dwSourceContext = 0;
		ULONG ulLineNumber    = 0;
		LONG ichCharPosition  = 0;
		hr = scriptError->lpVtbl->GetSourcePosition(scriptError, &dwSourceContext, &ulLineNumber, &ichCharPosition);
		printf("HRESULT : %08lx\n", hr);
   
    DPRINT("JSError: %s line[%d:%d]\n", ei.bstrDescription, ulLineNumber, ichCharPosition);

    hr = scriptError->lpVtbl->GetSourceLineText(scriptError, &line);
    
    if(hr == S_OK) {
      DPRINT("Line : %s\n", line);
    } else {
      DPRINT("Unable to retrieve line %08lx\n", hr);
    }
    return S_OK;
}

static STDMETHODIMP ActiveScript_GetLCID(IActiveScriptSite *this, LCID *plcid) {
    DPRINT("IActiveScriptSite::GetLCID");
    
    *plcid = GetUserDefaultLCID();
    return S_OK;
}

static STDMETHODIMP ActiveScript_GetDocVersionString(IActiveScriptSite *this, BSTR *version) {
    DPRINT("IActiveScriptSite::GetDocVersionString");  
    return S_OK;
}

static STDMETHODIMP ActiveScript_OnScriptTerminate(IActiveScriptSite *this, 
  const VARIANT *pvr, const EXCEPINFO *pei) 
{
    DPRINT("IActiveScriptSite::OnScriptTerminate");  
    return S_OK;
}

static STDMETHODIMP ActiveScript_OnStateChange(IActiveScriptSite *this, SCRIPTSTATE state) {
    DPRINT("IActiveScriptSite::OnStateChange");
    return S_OK;
}

static STDMETHODIMP ActiveScript_OnEnterScript(IActiveScriptSite *this) {
    DPRINT("IActiveScriptSite::OnEnterScript");
    return S_OK;
}

static STDMETHODIMP ActiveScript_OnLeaveScript(IActiveScriptSite *this) {
    DPRINT("IActiveScriptSite::OnLeaveScript");
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
    
    // signal to main thread script has finished
    mas->_SetEvent(mas->hEvent);
    
    return S_OK;
}