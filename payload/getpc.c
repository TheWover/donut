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

// Function to return the program counter.
// Always place this at the end of payload.
// Tested with x86 and x64 builds of MSVC 2017 and MinGW. YMMV.
#if defined(_MSC_VER) 
  #if defined(_M_X64)

    #define PC_CODE_SIZE 9 // sub rsp, 40 / call get_pc

    static char *get_pc_stub(void) {
      return (char*)_ReturnAddress() - PC_CODE_SIZE;
    }
    
    static char *get_pc(void) {
      return get_pc_stub();
    }

  #elif defined(_M_IX86)
    __declspec(naked) static char *get_pc(void) {
      __asm {
          call   pc_addr
        pc_addr:
          pop    eax
          sub    eax, 5
          ret
      }
    }
  #endif  
#elif defined(__GNUC__) 
  #if defined(__x86_64__)
    static char *get_pc(void) {
        __asm__ (
        "call   pc_addr\n"
      "pc_addr:\n"
        "pop    %rax\n"
        "sub    $5, %rax\n"
        "ret");
    }
  #elif defined(__i386__)
    static char *get_pc(void) {
        __asm__ (
        "call   pc_addr\n"
      "pc_addr:\n"
        "popl   %eax\n"
        "subl   $5, %eax\n"
        "ret");
    }
  #endif
#endif
