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

#ifndef IACTIVESCRIPT_H
#define IACTIVESCRIPT_H

#include "../include/donut.h"

    // required to load and run VBS or JS files
    typedef struct _IActiveScript           IActiveScript;
    typedef struct _IActiveScriptError      IActiveScriptError;
    typedef struct _IActiveScriptSite       IActiveScriptSite;
    typedef struct _IActiveScriptSiteWindow IActiveScriptSiteWindow;
    typedef struct _IActiveScriptParse32    IActiveScriptParse32;
    typedef struct _IActiveScriptParse64    IActiveScriptParse64;
    
    typedef enum tagSCRIPTSTATE { 
      SCRIPTSTATE_UNINITIALIZED = 0,
      SCRIPTSTATE_STARTED       = 1,
      SCRIPTSTATE_CONNECTED     = 2,
      SCRIPTSTATE_DISCONNECTED  = 3,
      SCRIPTSTATE_CLOSED        = 4,
      SCRIPTSTATE_INITIALIZED   = 5
    } SCRIPTSTATE;

    typedef enum tagSCRIPTTHREADSTATE { 
      SCRIPTTHREADSTATE_NOTINSCRIPT = 0,
      SCRIPTTHREADSTATE_RUNNING     = 1
    } SCRIPTTHREADSTATE;

    #define SCRIPTTHREADID_CURRENT 	0xFFFFFFFD 	// The currently executing thread.
    #define SCRIPTTHREADID_BASE 	  0xFFFFFFFE 	// The base thread; that is, the thread in which the scripting engine was instantiated.
    #define SCRIPTTHREADID_ALL 	    0xFFFFFFFF 	// All threads.

    typedef DWORD SCRIPTTHREADID;

#define SCRIPTITEM_ISPERSISTENT    0x00000001
#define SCRIPTITEM_ISVISIBLE       0x00000002
#define SCRIPTITEM_ISSOURCE        0x00000004
#define SCRIPTITEM_GLOBALMEMBERS   0x00000008
#define SCRIPTITEM_EXISTS          0x00000080
#define SCRIPTITEM_MULTIINSTANCE   0x00000100
#define SCRIPTITEM_CODEONLY        0x00000200

#define SCRIPTTEXT_ISPERSISTENT    0x00000001
#define SCRIPTTEXT_ISVISIBLE       0x00000002
#define SCRIPTTEXT_ISEXPRESSION    0x00000020
#define SCRIPTTEXT_KEEPDEFINITIONS 0x00000040
#define SCRIPTTEXT_ALLOWEXECUTION  0x00000400
#define SCRIPTTEXT_ALL_FLAGS      (SCRIPTTEXT_ISPERSISTENT    | \
                                   SCRIPTTEXT_ISVISIBLE       | \
                                   SCRIPTTEXT_ISEXPRESSION    | \
                                   SCRIPTTEXT_KEEPDEFINITIONS | \
                                   SCRIPTTEXT_ALLOWEXECUTION)
                                   
#define SCRIPTTEXT_HOSTMANAGESSOURCE   0x00000080    
#define SCRIPTINFO_IUNKNOWN            0x00000001
#define SCRIPTINFO_ITYPEINFO           0x00000002
#define SCRIPTINFO_ALL_FLAGS           (SCRIPTINFO_IUNKNOWN | SCRIPTINFO_ITYPEINFO)

    typedef struct IActiveScriptVtbl {
          BEGIN_INTERFACE
          
          HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
                IActiveScript * This,
              /* [in] */   REFIID riid,
              /* [annotation][iid_is][out] */ 
                 void **ppvObject);
          
          ULONG ( STDMETHODCALLTYPE *AddRef )( 
                          IActiveScript * This);
          
          ULONG ( STDMETHODCALLTYPE *Release )( 
                          IActiveScript * This);
          
          HRESULT ( STDMETHODCALLTYPE *SetScriptSite )( 
                          IActiveScript * This,
              /* [in] */  IActiveScriptSite *pass);
          
          HRESULT ( STDMETHODCALLTYPE *GetScriptSite )( 
                          IActiveScript * This,
              /* [in] */  REFIID riid,
              /* [iid_is][out] */   void **ppvObject);
          
          HRESULT ( STDMETHODCALLTYPE *SetScriptState )( 
                          IActiveScript * This,
              /* [in] */  SCRIPTSTATE ss);
          
          HRESULT ( STDMETHODCALLTYPE *GetScriptState )( 
                          IActiveScript * This,
              /* [out] */ SCRIPTSTATE *pssState);
          
          HRESULT ( STDMETHODCALLTYPE *Close )( 
                          IActiveScript * This);
          
          HRESULT ( STDMETHODCALLTYPE *AddNamedItem )( 
                          IActiveScript * This,
              /* [in] */  LPCOLESTR pstrName,
              /* [in] */  DWORD dwFlags);
          
          HRESULT ( STDMETHODCALLTYPE *AddTypeLib )( 
                          IActiveScript * This,
              /* [in] */  REFGUID rguidTypeLib,
              /* [in] */  DWORD dwMajor,
              /* [in] */  DWORD dwMinor,
              /* [in] */  DWORD dwFlags);
          
          HRESULT ( STDMETHODCALLTYPE *GetScriptDispatch )( 
                          IActiveScript * This,
              /* [in] */  LPCOLESTR pstrItemName,
              /* [out] */ IDispatch **ppdisp);
          
          HRESULT ( STDMETHODCALLTYPE *GetCurrentScriptThreadID )( 
                          IActiveScript * This,
              /* [out] */ SCRIPTTHREADID *pstidThread);
          
          HRESULT ( STDMETHODCALLTYPE *GetScriptThreadID )( 
                          IActiveScript * This,
              /* [in] */  DWORD dwWin32ThreadId,
              /* [out] */ SCRIPTTHREADID *pstidThread);
          
          HRESULT ( STDMETHODCALLTYPE *GetScriptThreadState )( 
                          IActiveScript * This,
              /* [in] */  SCRIPTTHREADID stidThread,
              /* [out] */ SCRIPTTHREADSTATE *pstsState);
          
          HRESULT ( STDMETHODCALLTYPE *InterruptScriptThread )( 
                          IActiveScript * This,
              /* [in] */  SCRIPTTHREADID stidThread,
              /* [in] */  const EXCEPINFO *pexcepinfo,
              /* [in] */  DWORD dwFlags);
          
          HRESULT ( STDMETHODCALLTYPE *Clone )( 
                          IActiveScript * This,
              /* [out] */ IActiveScript **ppscript);
          
          END_INTERFACE
      } IActiveScriptVtbl;

      typedef struct _IActiveScript {
          IActiveScriptVtbl *lpVtbl;
      } ActiveScript;
    
      typedef struct IActiveScriptParse32Vtbl {
          BEGIN_INTERFACE
          
          HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
                IActiveScriptParse32 * This,
              /* [in] */   REFIID riid,
              /* [annotation][iid_is][out] */ 
                void **ppvObject);
          
          ULONG ( STDMETHODCALLTYPE *AddRef )( 
                IActiveScriptParse32 * This);
          
          ULONG ( STDMETHODCALLTYPE *Release )( 
                IActiveScriptParse32 * This);
          
          HRESULT ( STDMETHODCALLTYPE *InitNew )( 
                IActiveScriptParse32 * This);
          
          HRESULT ( STDMETHODCALLTYPE *AddScriptlet )( 
                           IActiveScriptParse32 * This,
              /* [in] */   LPCOLESTR pstrDefaultName,
              /* [in] */   LPCOLESTR pstrCode,
              /* [in] */   LPCOLESTR pstrItemName,
              /* [in] */   LPCOLESTR pstrSubItemName,
              /* [in] */   LPCOLESTR pstrEventName,
              /* [in] */   LPCOLESTR pstrDelimiter,
              /* [in] */   DWORD dwSourceContextCookie,
              /* [in] */   ULONG ulStartingLineNumber,
              /* [in] */   DWORD dwFlags,
              /* [out] */  BSTR *pbstrName,
              /* [out] */  EXCEPINFO *pexcepinfo);
          
          HRESULT ( STDMETHODCALLTYPE *ParseScriptText )( 
                IActiveScriptParse32 * This,
              /* [in] */   LPCOLESTR pstrCode,
              /* [in] */   LPCOLESTR pstrItemName,
              /* [in] */   IUnknown *punkContext,
              /* [in] */   LPCOLESTR pstrDelimiter,
              /* [in] */   DWORD dwSourceContextCookie,
              /* [in] */   ULONG ulStartingLineNumber,
              /* [in] */   DWORD dwFlags,
              /* [out] */  VARIANT *pvarResult,
              /* [out] */  EXCEPINFO *pexcepinfo);
          
          END_INTERFACE
      } IActiveScriptParse32Vtbl;

      typedef struct _IActiveScriptParse32 {
          IActiveScriptParse32Vtbl *lpVtbl;
      } ActiveScriptParse32;
    
      typedef struct IActiveScriptParse64Vtbl {
          BEGIN_INTERFACE
          
          HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
                IActiveScriptParse64 * This,
              /* [in] */   REFIID riid,
              /* [annotation][iid_is][out] */ 
                 void **ppvObject);
          
          ULONG ( STDMETHODCALLTYPE *AddRef )( 
                IActiveScriptParse64 * This);
          
          ULONG ( STDMETHODCALLTYPE *Release )( 
                IActiveScriptParse64 * This);
          
          HRESULT ( STDMETHODCALLTYPE *InitNew )( 
                IActiveScriptParse64 * This);
          
          HRESULT ( STDMETHODCALLTYPE *AddScriptlet )( 
                          IActiveScriptParse64 *This,
              /* [in] */  LPCOLESTR            pstrDefaultName,
              /* [in] */  LPCOLESTR            pstrCode,
              /* [in] */  LPCOLESTR            pstrItemName,
              /* [in] */  LPCOLESTR            pstrSubItemName,
              /* [in] */  LPCOLESTR            pstrEventName,
              /* [in] */  LPCOLESTR            pstrDelimiter,
              /* [in] */  DWORDLONG            dwSourceContextCookie,
              /* [in] */  ULONG                ulStartingLineNumber,
              /* [in] */  DWORD                dwFlags,
              /* [out] */ BSTR                 *pbstrName,
              /* [out] */ EXCEPINFO            *pexcepinfo);
          
          HRESULT ( STDMETHODCALLTYPE *ParseScriptText )( 
                          IActiveScriptParse64 *This,
              /* [in] */  LPCOLESTR            pstrCode,
              /* [in] */  LPCOLESTR            pstrItemName,
              /* [in] */  IUnknown             *punkContext,
              /* [in] */  LPCOLESTR            pstrDelimiter,
              /* [in] */  DWORDLONG            dwSourceContextCookie,
              /* [in] */  ULONG                ulStartingLineNumber,
              /* [in] */  DWORD                dwFlags,
              /* [out] */ VARIANT              *pvarResult,
              /* [out] */ EXCEPINFO            *pexcepinfo);
          
          END_INTERFACE
      } IActiveScriptParse64Vtbl;

      typedef struct _IActiveScriptParse64 {
          IActiveScriptParse64Vtbl *lpVtbl;
      } ActiveScriptParse64;
      
      typedef struct _IActiveScriptSiteWindowVtbl {
          BEGIN_INTERFACE
          
          HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
                IActiveScriptSiteWindow * This,
              /* [in] */   REFIID riid,
              /* [annotation][iid_is][out] */ 
                 void **ppvObject);
          
          ULONG ( STDMETHODCALLTYPE *AddRef )( 
                IActiveScriptSiteWindow * This);
          
          ULONG ( STDMETHODCALLTYPE *Release )( 
                IActiveScriptSiteWindow * This);
          
          HRESULT ( STDMETHODCALLTYPE *GetWindow )( 
                IActiveScriptSiteWindow * This,
              /* [out] */  HWND *phwnd);
          
          HRESULT ( STDMETHODCALLTYPE *EnableModeless )( 
                IActiveScriptSiteWindow * This,
              /* [in] */ BOOL fEnable);
          
          END_INTERFACE
      } IActiveScriptSiteWindowVtbl;

      typedef struct _IActiveScriptSiteWindow {
        IActiveScriptSiteWindowVtbl *lpVtbl;
        ULONG                       m_cRef;
        PDONUT_INSTANCE             inst;
      } ActiveScriptSiteWindow;
    
      typedef struct _IActiveScriptErrorVtbl {
          BEGIN_INTERFACE
          
          HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
                IActiveScriptError * This,
              /* [in] */   REFIID riid,
              /* [annotation][iid_is][out] */ 
                 void **ppvObject);
          
          ULONG ( STDMETHODCALLTYPE *AddRef )( 
                IActiveScriptError * This);
          
          ULONG ( STDMETHODCALLTYPE *Release )( 
                IActiveScriptError * This);
          
          /* [local] */ HRESULT ( STDMETHODCALLTYPE *GetExceptionInfo )( 
              IActiveScriptError * This,
              /* [out] */ EXCEPINFO *pexcepinfo);
          
          HRESULT ( STDMETHODCALLTYPE *GetSourcePosition )( 
                IActiveScriptError * This,
              /* [out] */   DWORD *pdwSourceContext,
              /* [out] */   ULONG *pulLineNumber,
              /* [out] */   LONG *plCharacterPosition);
          
          HRESULT ( STDMETHODCALLTYPE *GetSourceLineText )( 
                IActiveScriptError * This,
              /* [out] */  BSTR *pbstrSourceLine);
          
          END_INTERFACE
      } IActiveScriptErrorVtbl;

      typedef struct _IActiveScriptError {
          IActiveScriptErrorVtbl *lpVtbl;
      } ActiveScriptError;

      typedef struct _IActiveScriptSiteVtbl {
          BEGIN_INTERFACE
          
          HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
                IActiveScriptSite * This,
              /* [in] */   REFIID riid,
              /* [annotation][iid_is][out] */ 
                 void **ppvObject);
          
          ULONG ( STDMETHODCALLTYPE *AddRef )( 
                IActiveScriptSite * This);
          
          ULONG ( STDMETHODCALLTYPE *Release )( 
                IActiveScriptSite * This);
          
          HRESULT ( STDMETHODCALLTYPE *GetLCID )( 
                IActiveScriptSite * This,
              /* [out] */   LCID *plcid);
          
          HRESULT ( STDMETHODCALLTYPE *GetItemInfo )( 
                IActiveScriptSite * This,
              /* [in] */   LPCOLESTR pstrName,
              /* [in] */ DWORD dwReturnMask,
              /* [out] */    IUnknown **ppiunkItem,
              /* [out] */    ITypeInfo **ppti);
          
          HRESULT ( STDMETHODCALLTYPE *GetDocVersionString )( 
                IActiveScriptSite * This,
              /* [out] */    BSTR *pbstrVersion);
          
          HRESULT ( STDMETHODCALLTYPE *OnScriptTerminate )( 
                IActiveScriptSite * This,
              /* [in] */   const VARIANT *pvarResult,
              /* [in] */   const EXCEPINFO *pexcepinfo);
          
          HRESULT ( STDMETHODCALLTYPE *OnStateChange )( 
                IActiveScriptSite * This,
              /* [in] */ SCRIPTSTATE ssScriptState);
          
          HRESULT ( STDMETHODCALLTYPE *OnScriptError )( 
                IActiveScriptSite * This,
              /* [in] */    IActiveScriptError *pscripterror);
          
          HRESULT ( STDMETHODCALLTYPE *OnEnterScript )( 
                IActiveScriptSite * This);
          
          HRESULT ( STDMETHODCALLTYPE *OnLeaveScript )( 
                IActiveScriptSite * This);
          
          END_INTERFACE
      } IActiveScriptSiteVtbl;

      typedef struct _IActiveScriptSite {
        IActiveScriptSiteVtbl   *lpVtbl;
        ULONG                   m_cRef;
      } ActiveScriptSite;

#ifdef _WIN64
#define     IActiveScriptParse     IActiveScriptParse64
#define IID_IActiveScriptParse IID_IActiveScriptParse64
#else
#define     IActiveScriptParse     IActiveScriptParse32
#define IID_IActiveScriptParse IID_IActiveScriptParse32
#endif

static VOID ActiveScript_New(PDONUT_INSTANCE inst, IActiveScriptSite *this);

static STDMETHODIMP ActiveScript_QueryInterface(IActiveScriptSite *this, REFIID riid, void **ppv);
static STDMETHODIMP_(ULONG) ActiveScript_AddRef(IActiveScriptSite *this);
static STDMETHODIMP_(ULONG) ActiveScript_Release(IActiveScriptSite *this);

// Informs the host that the scripting engine has begun executing the script code.
static STDMETHODIMP ActiveScript_OnEnterScript(IActiveScriptSite *this);

// Informs the host that the scripting engine has returned from executing script code.
static STDMETHODIMP ActiveScript_OnLeaveScript(IActiveScriptSite *this);

// Retrieves the locale identifier that the host uses for displaying user-interface elements.
static STDMETHODIMP ActiveScript_GetLCID(IActiveScriptSite *this, LCID *lcid);

// Retrieves a host-defined string that uniquely identifies the current document version from the host's point of view.
static STDMETHODIMP ActiveScript_GetDocVersionString(IActiveScriptSite *this, BSTR *version);

// Informs the host that an execution error occurred while the engine was running the script.
static STDMETHODIMP ActiveScript_OnScriptError(IActiveScriptSite *this, IActiveScriptError *scriptError);

// Informs the host that the scripting engine has changed states.
static STDMETHODIMP ActiveScript_OnStateChange(IActiveScriptSite *this, SCRIPTSTATE state);

// Obtains information about an item that was added to an engine through a call to the IActiveScript::AddNamedItem method.
static STDMETHODIMP ActiveScript_GetItemInfo(IActiveScriptSite *this, LPCOLESTR objectName, DWORD dwReturnMask, IUnknown **objPtr, ITypeInfo **typeInfo);

// Called when the script has completed execution.
static STDMETHODIMP ActiveScript_OnScriptTerminate(IActiveScriptSite *this, const VARIANT *pvr, const EXCEPINFO *pei);

// ################################################# IActiveScriptSiteWindow ###############################################
static VOID ActiveScriptSiteWindow_New(PDONUT_INSTANCE inst, IActiveScriptSiteWindow *this);

// IUnknown      
static STDMETHODIMP ActiveScriptSiteWindow_QueryInterface(IActiveScriptSiteWindow *this, REFIID riid, void **ppv);
static STDMETHODIMP_(ULONG) ActiveScriptSiteWindow_AddRef(IActiveScriptSiteWindow *this);
static STDMETHODIMP_(ULONG) ActiveScriptSiteWindow_Release(IActiveScriptSiteWindow *this);

// IActiveScriptSiteWindow
static STDMETHODIMP ActiveScriptSiteWindow_GetWindow(IActiveScriptSiteWindow *iface, HWND *phwnd);
static STDMETHODIMP ActiveScriptSiteWindow_EnableModeless(IActiveScriptSiteWindow *iface, BOOL fEnable);

#endif

