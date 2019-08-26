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

VOID RunXSL(PDONUT_INSTANCE inst) {
    IXMLDOMDocument *pDoc; 
    IXMLDOMNode     *pNode;
    HRESULT         hr;
    PWCHAR          xsl_str;
    VARIANT_BOOL    loaded;
    BSTR            res;
    PDONUT_MODULE   mod;
    ULONG64         len;
    UCHAR           c;
    
    if(inst->type == DONUT_INSTANCE_PIC) {
      DPRINT("Using module embedded in instance");
      mod = (PDONUT_MODULE)&inst->module.x;
    } else {
      DPRINT("Loading module from allocated memory");
      mod = inst->module.p;
    }
    
    // 1. Allocate RW memory for unicode format of script
    xsl_str = (PWCHAR)inst->api.VirtualAlloc(
        NULL, 
        (inst->mod_len + 1) * sizeof(WCHAR), 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE);
        
    if(xsl_str != NULL) {
      // 2. Convert string to unicode.
      inst->api.MultiByteToWideChar(CP_ACP, 0, mod->data, 
        -1, xsl_str, mod->len * sizeof(WCHAR));
    
      // 3. Initialize COM
      DPRINT("CoInitializeEx");
      hr = inst->api.CoInitializeEx(NULL, COINIT_MULTITHREADED);

      if(hr == S_OK) {
        // 4. Instantiate XMLDOMDocument object
        DPRINT("CoCreateInstance");
        hr = inst->api.CoCreateInstance(
          &inst->xCLSID_DOMDocument30, 
          NULL, CLSCTX_INPROC_SERVER,
          &inst->xIID_IXMLDOMDocument, 
          (void**)&pDoc);
          
        if(hr == S_OK) {
          // 5. load XSL file
          DPRINT("IXMLDOMDocument::loadXML");
          hr = pDoc->lpVtbl->loadXML(pDoc, (BSTR)xsl_str, &loaded);
          DPRINT("HRESULT: %08lx loaded : %s", 
            hr, loaded ? "TRUE" : "FALSE");
            
          if(hr == S_OK && loaded) {
            // 6. query node interface
            DPRINT("IXMLDOMDocument::QueryInterface");
            hr = pDoc->lpVtbl->QueryInterface(
              pDoc, &inst->xIID_IXMLDOMNode, (void **)&pNode);
              
            if(hr == S_OK) {
              DPRINT("HRESULT: %08lx", hr);
              // 7. execute script
              DPRINT("IXMLDOMDocument::transformNode");
              hr = pDoc->lpVtbl->transformNode(pDoc, pNode, &res);
              DPRINT("HRESULT: %08lx", hr);
              pNode->lpVtbl->Release(pNode);
            }
          }
          pDoc->lpVtbl->Release(pDoc);
        }
        DPRINT("CoUninitialize");
        inst->api.CoUninitialize();
      }
      DPRINT("Erasing XSL from memory.");
      Memset(xsl_str, 0, (inst->mod_len + 1) * sizeof(WCHAR));
      
      DPRINT("VirtualFree()");
      inst->api.VirtualFree(xsl_str, 0, MEM_RELEASE | MEM_DECOMMIT);
    }
}
