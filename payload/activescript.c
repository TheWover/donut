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

// initialize virtual function table
static VOID ActiveScript_New(PDONUT_INSTANCE inst, IActiveScriptSite *this) {
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
    
    // Initialize IUnknown
    mas->site.lpVtbl->QueryInterface      = ADR(LPVOID, ActiveScript_QueryInterface);
    mas->site.lpVtbl->AddRef              = ADR(LPVOID, ActiveScript_AddRef);
    mas->site.lpVtbl->Release             = ADR(LPVOID, ActiveScript_Release);
    
    // Initialize IActiveScriptSite
    mas->site.lpVtbl->GetLCID             = ADR(LPVOID, ActiveScript_GetLCID);
    mas->site.lpVtbl->GetItemInfo         = ADR(LPVOID, ActiveScript_GetItemInfo);
    mas->site.lpVtbl->GetDocVersionString = ADR(LPVOID, ActiveScript_GetDocVersionString);
    mas->site.lpVtbl->OnScriptTerminate   = ADR(LPVOID, ActiveScript_OnScriptTerminate);
    mas->site.lpVtbl->OnStateChange       = ADR(LPVOID, ActiveScript_OnStateChange);
    mas->site.lpVtbl->OnScriptError       = ADR(LPVOID, ActiveScript_OnScriptError);
    mas->site.lpVtbl->OnEnterScript       = ADR(LPVOID, ActiveScript_OnEnterScript);
    mas->site.lpVtbl->OnLeaveScript       = ADR(LPVOID, ActiveScript_OnLeaveScript);
    
    mas->site.m_cRef                      = 0;
    mas->inst                             = inst;
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
  
    _InterlockedIncrement(&mas->site.m_cRef);
  
    DPRINT("IActiveScriptSite::AddRef : m_cRef : %i\n", mas->site.m_cRef);
  
    return mas->site.m_cRef;
}

static STDMETHODIMP_(ULONG) ActiveScript_Release(IActiveScriptSite *this) {
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
    
    ULONG ulRefCount = _InterlockedDecrement(&mas->site.m_cRef);

    DPRINT("IActiveScriptSite::Release : m_cRef : %i\n", ulRefCount);    
    return ulRefCount;
}

static STDMETHODIMP ActiveScript_GetItemInfo(IActiveScriptSite *this, 
  LPCOLESTR objectName, DWORD dwReturnMask, 
  IUnknown **objPtr, ITypeInfo **ppti) 
{
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
      
    DPRINT("IActiveScriptSite::GetItemInfo");   
    
    if(dwReturnMask & SCRIPTINFO_ITYPEINFO) {
        DPRINT("Caller is requesting SCRIPTINFO_ITYPEINFO.");
        if(ppti == NULL) return E_POINTER;
        
        mas->wscript.lpTypeInfo->lpVtbl->AddRef(mas->wscript.lpTypeInfo);
        *ppti = mas->wscript.lpTypeInfo;
    }

    if(dwReturnMask & SCRIPTINFO_IUNKNOWN) {
      DPRINT("Caller is requesting SCRIPTINFO_IUNKNOWN.");
      if(objPtr == NULL) return E_POINTER;
        
      mas->wscript.lpVtbl->AddRef(&mas->wscript);
      *objPtr = (IUnknown*)&mas->wscript;
    }

    return S_OK;
}

static STDMETHODIMP ActiveScript_OnScriptError(IActiveScriptSite *this, 
  IActiveScriptError *scriptError) 
{
    DPRINT("IActiveScriptSite::OnScriptError");
    
    EXCEPINFO ei;
    DWORD     dwSourceContext = 0;
    ULONG     ulLineNumber    = 0;
    LONG      ichCharPosition = 0;
    HRESULT   hr;
    
    Memset(&ei, 0, sizeof(EXCEPINFO));
    
    DPRINT("IActiveScriptError::GetExceptionInfo");
    hr = scriptError->lpVtbl->GetExceptionInfo(scriptError, &ei);
    if(hr == S_OK) {
      DPRINT("IActiveScriptError::GetSourcePosition");
      hr = scriptError->lpVtbl->GetSourcePosition(
        scriptError, &dwSourceContext, 
        &ulLineNumber, &ichCharPosition);
      if(hr == S_OK) {
        DPRINT("JSError: %ws line[%d:%d]\n", 
          ei.bstrDescription, ulLineNumber, ichCharPosition);
      }
    }
    return S_OK;
}

static STDMETHODIMP ActiveScript_GetLCID(IActiveScriptSite *this, LCID *plcid) {
    DPRINT("IActiveScriptSite::GetLCID");
    MyIActiveScriptSite *mas = (MyIActiveScriptSite*)this;
    
    *plcid = mas->inst->api.GetUserDefaultLCID();
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
    
    return S_OK;
}