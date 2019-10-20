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

#ifndef AMSI_H
#define AMSI_H

#include <windows.h>

DECLARE_HANDLE(HAMSICONTEXT);
DECLARE_HANDLE(HAMSISESSION);

    typedef struct _IAmsiStream             IAmsiStream;
    typedef struct _IAntimalware            IAntimalware;
    typedef struct _IAntimalwareProvider    IAntimalwareProvider;
    
typedef enum tagAMSI_RESULT {
    // No detection found. Result likely not going to change after future definition update.
    // a.k.a. known good
    AMSI_RESULT_CLEAN        = 0,
    // No detection found. Result might change after future definition update.
    AMSI_RESULT_NOT_DETECTED = 1,
    // Detection found. It is recommended to abort executing the content if it is executable, e.g. a script.
    // Return result of 1 - 32767 is estimated risk level that an antimalware provider might indicate.
    // The large the result, the riskier to continue.
    // Any return result equal to or larger than 32768 is consider malware and should be blocked.
    // These values are provider specific, and may indicate malware family or ID.
    // An application should use AmsiResultIsMalware() to determine whether the content should be blocked.
    AMSI_RESULT_DETECTED     = 32768,
} AMSI_RESULT;

typedef enum tagAMSI_ATTRIBUTE {
    // Name/version/GUID string of the calling application.
    AMSI_ATTRIBUTE_APP_NAME     = 0,
    // LPWSTR, filename, URL, script unique id etc.
    AMSI_ATTRIBUTE_CONTENT_NAME = 1,
    // ULONGLONG, size of the input. Mandatory.
    AMSI_ATTRIBUTE_CONTENT_SIZE = 2,
    // PVOID, memory address if content is fully loaded in memory. Mandatory unless
    // Read() is implemented instead to support on-demand content retrieval.
    AMSI_ATTRIBUTE_CONTENT_ADDRESS = 3,
    // PVOID, session is used to associate different scan calls, e.g. if the contents
    // to be scanned belong to the sample original script. Return nullptr if content
    // is self-contained. Mandatory.
    AMSI_ATTRIBUTE_SESSION = 4,
} AMSI_ATTRIBUTE;

    typedef struct IAmsiStreamVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IAmsiStream * This,
            REFIID riid,
            void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAmsiStream * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAmsiStream * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetAttribute )( 
            IAmsiStream * This,
            AMSI_ATTRIBUTE attribute,
            ULONG dataSize,
            unsigned char *data,
            ULONG *retData);
        
        HRESULT ( STDMETHODCALLTYPE *Read )( 
            IAmsiStream * This,
            ULONGLONG position,
            ULONG size,
            unsigned char *buffer,
            ULONG *readSize);
        
        END_INTERFACE
    } IAmsiStreamVtbl;

    typedef struct _IAmsiStream {
        IAmsiStreamVtbl *lpVtbl;
    } AmsiStream;
    
    typedef struct IAntimalwareProviderVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IAntimalwareProvider * This,
            REFIID riid,
            void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAntimalwareProvider * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAntimalwareProvider * This);
        
        HRESULT ( STDMETHODCALLTYPE *Scan )( 
            IAntimalwareProvider * This,
            IAmsiStream *stream,
            AMSI_RESULT *result);
        
        void ( STDMETHODCALLTYPE *CloseSession )( 
            IAntimalwareProvider * This,
            ULONGLONG session);
        
        HRESULT ( STDMETHODCALLTYPE *DisplayName )( 
            IAntimalwareProvider * This,
            LPWSTR *displayName);
        
        END_INTERFACE
    } IAntimalwareProviderVtbl;

    typedef struct _IAntimalwareProvider {
        IAntimalwareProviderVtbl *lpVtbl;
    } AntimalwareProvider;
    
    typedef struct IAntimalwareVtbl {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface)(
            IAntimalware *This,
            REFIID riid, 
            void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IAntimalware * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IAntimalware * This);
        
        HRESULT ( STDMETHODCALLTYPE *Scan )( 
            IAntimalware * This,
            IAmsiStream *stream,
            AMSI_RESULT *result,
            IAntimalwareProvider **provider);
        
        void ( STDMETHODCALLTYPE *CloseSession )( 
            IAntimalware * This,
            ULONGLONG session);
        
        END_INTERFACE
    } IAntimalwareVtbl;

    typedef struct _IAntimalware {
        IAntimalwareVtbl *lpVtbl;
    } Antimalware;
    
typedef struct tagHAMSICONTEXT {
    DWORD        Signature;          // "AMSI" or 0x49534D41
    PWCHAR       AppName;            // set by AmsiInitialize
    IAntimalware *Antimalware;       // set by AmsiInitialize
    DWORD        SessionCount;       // increased by AmsiOpenSession
} _HAMSICONTEXT, *_PHAMSICONTEXT;

#endif