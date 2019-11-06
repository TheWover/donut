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

VOID RunScript(PDONUT_INSTANCE inst) {
    HRESULT                     hr;
    IActiveScriptParse          *parser;
    IActiveScript               *engine;
    MyIActiveScriptSite         mas;
    IActiveScriptSiteVtbl       activescript_vtbl;
    IActiveScriptSiteWindowVtbl siteWnd_vtbl;
    IHostVtbl                   wscript_vtbl;
    PDONUT_MODULE               mod;
    PWCHAR                      script;
    ULONG64                     len;
    BSTR                        obj;
    BOOL                        disabled;
    WCHAR                       buf[DONUT_MAX_NAME+1];
    
    if(inst->type == DONUT_INSTANCE_PIC) {
      DPRINT("Using module embedded in instance");
      mod = (PDONUT_MODULE)&inst->module.x;
    } else {
      DPRINT("Loading module from allocated memory");
      mod = inst->module.p;
    }
    
    // 1. Allocate memory for unicode format of script
    script = (PWCHAR)inst->api.VirtualAlloc(
        NULL, 
        (inst->mod_len + 1) * sizeof(WCHAR), 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE);
        
    // 2. Convert string to unicode.
    if(script != NULL) {
      // 2. Convert string to unicode.
      inst->api.MultiByteToWideChar(CP_ACP, 0, mod->data, 
        -1, script, mod->len * sizeof(WCHAR));
    
      // setup the IActiveScriptSite interface
      mas.site.lpVtbl = (IActiveScriptSiteVtbl*)&activescript_vtbl;
      ActiveScript_New(inst, &mas.site);
      
      // setup the IActiveScriptSiteWindow interface for GUI stuff
      mas.siteWnd.lpVtbl = (IActiveScriptSiteWindowVtbl*)&siteWnd_vtbl;
      ActiveScriptSiteWindow_New(inst, &mas.siteWnd);
      
      // setup the IHost interface for WScript object
      mas.wscript.lpVtbl = (IHostVtbl*)&wscript_vtbl;
      Host_New(inst, &mas.wscript);
      
      // 4. Initialize COM, MyIActiveScriptSite 
      DPRINT("CoInitializeEx");
      hr = inst->api.CoInitializeEx(NULL, COINIT_MULTITHREADED);
      
      if(hr == S_OK) {
        // 5. Instantiate the active script engine
        DPRINT("CoCreateInstance(IID_IActiveScript)");
        
        hr = inst->api.CoCreateInstance(
          &inst->xCLSID_ScriptLanguage, 0, 
          CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER, 
          &inst->xIID_IActiveScript, (void **)&engine);
      
        if(hr == S_OK) {
          // 6. Get IActiveScriptParse object from engine
          DPRINT("IActiveScript::QueryInterface(IActiveScriptParse)");
          
          hr = engine->lpVtbl->QueryInterface(
            engine, 
            #ifdef _WIN64
            &inst->xIID_IActiveScriptParse64,
            #else
            &inst->xIID_IActiveScriptParse32,
            #endif      
            (void **)&parser);
            
          if(hr == S_OK) {
            // 7. Initialize parser
            DPRINT("IActiveScriptParse::InitNew");
            hr = parser->lpVtbl->InitNew(parser);
            
            if(hr == S_OK) {
              // 8. Set custom script interface
              DPRINT("IActiveScript::SetScriptSite");
              mas.wscript.lpEngine = engine;
              
              hr = engine->lpVtbl->SetScriptSite(
                engine, (IActiveScriptSite *)&mas);
              
              if(hr == S_OK) {
                DPRINT("IActiveScript::AddNamedItem(\"%s\")", inst->wscript);
                ansi2unicode(inst, inst->wscript, buf);
                obj = inst->api.SysAllocString(buf);
                hr = engine->lpVtbl->AddNamedItem(engine, (LPCOLESTR)obj, SCRIPTITEM_ISVISIBLE);
                inst->api.SysFreeString(obj);
                
                if(hr == S_OK) {
                  // 9. Load script
                  DPRINT("IActiveScriptParse::ParseScriptText");
                  hr = parser->lpVtbl->ParseScriptText(
                    parser, (LPCOLESTR)script, NULL, NULL, NULL, 0, 0, 0, NULL, NULL);
                    
                  if(hr == S_OK) {
                    // 10. Run script
                    DPRINT("IActiveScript::SetScriptState(SCRIPTSTATE_CONNECTED)");
                    hr = engine->lpVtbl->SetScriptState(
                      engine, SCRIPTSTATE_CONNECTED);
                    
                    // SetScriptState blocks here
                  }
                }
              }
            }
            DPRINT("IActiveScriptParse::Release");
            parser->lpVtbl->Release(parser);
          }
          DPRINT("IActiveScript::Close");
          engine->lpVtbl->Close(engine);
          
          DPRINT("IActiveScript::Release");
          engine->lpVtbl->Release(engine);
        }
      }
      DPRINT("Erasing script from memory");
      Memset(script, 0, (inst->mod_len + 1) * sizeof(WCHAR));
      
      DPRINT("VirtualFree(script)");
      inst->api.VirtualFree(script, 0, MEM_RELEASE | MEM_DECOMMIT);
    }
}

#include "activescript.c"
#include "wscript.c"
