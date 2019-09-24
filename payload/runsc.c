
/**
  Copyright © 2016-2019 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#if defined(_WIN32) || defined(_WIN64)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0502
#endif
#define WIN
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_  
#endif
#include <windows.h>
#include <shlwapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define close closesocket
#define SHUT_RDWR SD_BOTH
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <fcntl.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>

#define RSC_CLIENT 0
#define RSC_SERVER 1
#define RSC_EXEC   2

#define RSC_SEND   0
#define RSC_RECV   1

#define DEFAULT_PORT "4444"

// structure for parameters
typedef struct _args_t {
  int      s, r;
  char     *port, *address, *file;
  #ifdef WIN
  char     *modules;
  #endif
  int      port_nbr, ai_family, mode, sim, tx_mode, ai_addrlen, dbg;
  struct   sockaddr *ai_addr;
  struct   sockaddr_in v4;
  struct   sockaddr_in6 v6;
  char     ip[INET6_ADDRSTRLEN];
  uint32_t code_len;
  void     *code;
} args_t;

#ifdef WIN
/**F*****************************************************************/
void xstrerror (char *fmt, ...) 
/**
 * PURPOSE : Display windows error
 *
 * RETURN :  Nothing
 *
 * NOTES :   None
 *
 *F*/
{
  char    *error=NULL;
  va_list arglist;
  char    buffer[2048];
  DWORD   dwError=GetLastError();
  
  va_start (arglist, fmt);
  wvnsprintf (buffer, sizeof(buffer) - 1, fmt, arglist);
  va_end (arglist);
  
  if (FormatMessage (
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
      (LPSTR)&error, 0, NULL))
  {
    printf ("[ %s : %s\n", buffer, error);
    LocalFree (error);
  } else {
    printf ("[ %s : %i\n", buffer, dwError);
  }
}
#else
#define xstrerror printf
#endif

char *addr2ip(args_t *p)
{
  void *src;
#ifdef WIN
  DWORD ip_size=INET6_ADDRSTRLEN;
  WSAAddressToString (p->ai_addr, p->ai_addrlen, 
    NULL, (char*)p->ip, &ip_size);
#else
  if (p->ai_family==AF_INET) {
    src=(void*)&p->v4.sin_addr;
  } else {
    src=(void*)&p->v6.sin6_addr;
  }
  inet_ntop(p->ai_family, src, p->ip, INET6_ADDRSTRLEN);
#endif
  return p->ip;
}

int init_network (args_t *p)
/**
 * PURPOSE : initialize winsock for windows, resolve network address
 *
 * RETURN :  1 for okay else 0
 *
 * NOTES :   None
 *
 *F*/
{
  struct addrinfo *list=NULL, *e=NULL;
  struct addrinfo hints;
  int             r, t;
  
  // initialize winsock if windows
#ifdef WIN
  WSADATA wsa;
  WSAStartup (MAKEWORD (2, 0), &wsa);
#endif

  r=0;
  // set network address length to zero
  p->ai_addrlen = 0;
  
  // if no address supplied
  if (p->address==NULL)
  {
    // is it ipv4?
    if (p->ai_family==AF_INET) {
      p->v4.sin_family      = AF_INET; 
      p->v4.sin_port        = htons((u_short)p->port_nbr);
      p->v4.sin_addr.s_addr = INADDR_ANY;
      p->ai_addr            = (struct sockaddr*)&p->v4;
      p->ai_addrlen         = sizeof (struct sockaddr_in);
    } else {
      // else it's ipv6
      p->v6.sin6_family     = AF_INET6;
      p->v6.sin6_port       = htons((u_short)p->port_nbr);
      p->v6.sin6_addr       = in6addr_any;
      p->ai_addr            = (struct sockaddr*)&p->v6;
      p->ai_addrlen         = sizeof (struct sockaddr_in6);
    }
  } else {
    memset (&hints, 0, sizeof (hints));

    hints.ai_flags    = AI_PASSIVE;
    hints.ai_family   = p->ai_family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;    
    
    // get all network addresses
    t=getaddrinfo (p->address, p->port, &hints, &list);
    if (t == 0) 
    {
      for (e=list; e!=NULL; e=e->ai_next) 
      {
        // copy to ipv4 structure
        if (p->ai_family==AF_INET) {
          memcpy (&p->v4, e->ai_addr, e->ai_addrlen);
          p->ai_addr     = (struct sockaddr*)&p->v4;        
        } else {
          // ipv6 structure
          memcpy (&p->v6, e->ai_addr, e->ai_addrlen);
          p->ai_addr     = (struct sockaddr*)&p->v6;
        }
        // assign size of structure
        p->ai_addrlen = e->ai_addrlen;
        break;
      }
      freeaddrinfo (list);
    } else {
      xstrerror ("getaddrinfo");
    }
  }
  return p->ai_addrlen;
}

void debug(void *bin) 
{
  // 
  //__builtin_trap();
  //raise(SIGTRAP);
}

// allocate read/write and executable memory
// copy data from p->code and execute
void xcode(args_t *p)
{
  void *bin;
  int  i;
  int  fd[2048];
  
  if (p->code_len == 0) {
    printf("[ no code to execute.\n");
    return;
  }
  printf ("[ executing code...");
    
#ifdef WIN
  bin=VirtualAlloc (0, p->code_len, 
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
  bin=mmap (0, p->code_len, 
    PROT_EXEC | PROT_WRITE | PROT_READ, 
    MAP_ANON  | MAP_PRIVATE, -1, 0);
#endif
  if (bin!=NULL)
  {
    memcpy (bin, p->code, p->code_len);
    // create file/socket descriptors to simulate real system 
    // created interesting results on openbsd with limits
    // to how many files could be open at once..
    // 
    if (p->sim) {
      #ifndef WIN
      for (i=0; i<p->sim && p->sim<2048; i++) {
        fd[i]=socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      }
      #else
      // todo
      for (i=0; i<p->sim && p->sim<2048; i++) {
      }
      #endif
    }
    
    // debug the code?
    if (p->dbg) {
      #if defined(_WIN32) || defined(_WIN64)
        DebugBreak();
      #else
        raise(SIGTRAP);
      #endif    
    }
    
    // execute
    ((void(*)())bin)();
    
    printf("OK!\n");
    
    if (p->sim) {
      #ifndef WIN
      // close all descriptors
      for (i=0; i<p->sim && p->sim<2048; i++) {
        close(fd[i]);
      }
      #else
        // todo
      #endif
    }
#ifdef WIN
    VirtualFree (bin, 0, MEM_RELEASE | MEM_DECOMMIT);
#else
    munmap (bin, p->code_len);
#endif
  }
}

void send_data(args_t *p, int s) {
    FILE     *fd;
    int      outlen, len, opt;
    uint32_t sum;
    uint8_t  buf[BUFSIZ];
        
    // open file for read in binary mode
    printf ("[ opening %s for read\n", p->file);
    fd = fopen(p->file, "rb");
    
    if (fd != NULL)
    {
      // send contents of file
      printf ("[ sending data\n");
      for (;;) {
        // read block
        outlen = fread(buf, sizeof(uint8_t), BUFSIZ, fd);
        // zero or less indicates EOF
        if (outlen <= 0) break;
        // send contents
        for (sum=0; sum<outlen; sum += len) {
          len=send (s, &buf[sum], outlen - sum, 0);
          if (len <= 0) break;
        }
        p->code_len += sum;
        if (outlen != sum) break;
      }
      printf ("[ sent %i bytes\n", p->code_len);
      fclose(fd);
    }
}

void recv_data(args_t *p, int s) {
    int            opt, r;
    fd_set         fds;
    struct timeval tv;
    void           *pv;
    
    p->code_len = 0;
    p->code     = malloc(BUFSIZ);
   
    // set to non-blocking mode
    #ifdef WIN
      opt=1;
      ioctlsocket (s, FIONBIO, (u_long*)&opt);
    #else
      opt=fcntl(s, F_GETFL, 0);
      fcntl(s, F_SETFL, opt | O_NONBLOCK);
    #endif
    // keep reading until remote disconnects or we run out of memory
    printf ("[ receiving data\n");
    
    for (;;) {
      FD_ZERO(&fds);
      FD_SET(s, &fds);
    
      tv.tv_sec  = 5;
      tv.tv_usec = 0;
      r = select(FD_SETSIZE, &fds, 0, 0, &tv);
      
      if (r <= 0) {
        printf ("[ waiting for data timed out or failed\n");
        break;
      }
      // receive a block
      r = recv(s, (uint8_t*)p->code + p->code_len, BUFSIZ, 0);
      if (r <= 0) break;
      p->code_len += r;
      // resize buffer
      pv = realloc(p->code, p->code_len + BUFSIZ);
      // on error, free pointer
      if(pv == NULL) {
        p->code_len = 0;
        free(p->code);
        p->code = NULL;
        printf("[ error: out of memory.\n");
        break;
      }
      p->code = pv;
    }
    if(p->code_len != 0) {
      printf ("[ received %i bytes\n", p->code_len);
    }
}

// 
int ssr (args_t *p)
/**
 * PURPOSE : send a shellcode or receive one from remote system and execute it
 *
 * RETURN :  0 or length of shellcode sent/received
 *
 * NOTES :   None
 *
 *F*/
{
    int             s, opt, r, t;
    fd_set          fds;
    struct timeval  tv;
    
    p->code_len=0;
    
    // create socket
    printf ("[ creating socket\n");
    s = socket(p->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return 0;
        
    // ensure we can reuse socket
    t=1;
    setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char*)&t, sizeof (t));
    
    // bind to port
    printf ("[ binding to port %s\n", p->port);
    r = bind(s, p->ai_addr, p->ai_addrlen);
    if (r == 0) {
      // listen
      r = listen (s, 1);
      if (r == 0) {
        printf ("[ waiting for connections on %s\n", addr2ip(p));
        if (r == 0) {
          t = accept(s, p->ai_addr, &p->ai_addrlen);
          printf ("[ accepting connection from %s\n", addr2ip(p));
          if (t > 0) {
            if (p->tx_mode == RSC_SEND) {
              send_data(p, t);
            } else {
              recv_data(p, t);
              xcode(p);
            }
          }
        }
        // close socket to peer
        shutdown(t, SHUT_RDWR);
        close(t);
      } else {
        perror("listen");
      }
    } else {
      perror("bind");
    }
    // close listening socket
    shutdown(s, SHUT_RDWR);
    close(s);
    
    return p->code_len;
}

/**F*****************************************************************/
int csr (args_t *p)
/**
 * PURPOSE : opens connection to remote system and sends shellcode
 *
 * RETURN :  0 or 1
 *
 * NOTES :   None
 *
 *F*/
{
    int            s, r, opt;
    fd_set         fds;
    struct timeval tv;
    
    printf ("[ creating socket\n");
    s = socket(p->ai_family, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) return 0;
    
    // try connect to remote
    printf ("[ connecting to %s\n", addr2ip(p));
    r = connect(s, p->ai_addr, p->ai_addrlen);
    
    if (r == 0) {
      if (p->tx_mode==RSC_SEND) {
        send_data(p, s);
      } else {
        recv_data(p, s);
        xcode(p);
      }
    } else {
      xstrerror("connect");
    }
    printf ("[ closing connection\n");
    shutdown(s, SHUT_RDWR);
    close(s);
    return 1;
}

/**F*****************************************************************/
void xfile(args_t *p)
/**
 * PURPOSE : read contents of shellcode and attempt to execute it locally
 *
 * RETURN :  Nothing
 *
 * NOTES :   None
 *
 *F*/
{
    FILE    *fd;
    int     len;
    void    *pv;
    
    p->code_len = 0;
    p->code     = NULL;
    
    printf ("[ reading code from %s\n", p->file);
    fd = fopen(p->file, "rb");
    
    if (fd == NULL) {
      xstrerror("fopen(\"%s\")", p->file);
      return;
    }
    // read contents of file
    for (;;) {
      // first loop? allocate block
      if(p->code == NULL) {
        p->code = malloc(BUFSIZ);
      }
      // read a block of data
      len = fread((uint8_t*)p->code + p->code_len, sizeof(uint8_t), BUFSIZ, fd);
      if (len <= 0) break;
      p->code_len += len;
      // resize buffer for next read
      pv = realloc(p->code, p->code_len + BUFSIZ);
      
      if(pv == NULL) {
        p->code_len = 0;
        free(p->code);
        p->code = NULL;
        printf("[ error: out of memory!.\n");
        break;
      }
      p->code = pv;
    }
    fclose(fd);
    
    if(p->code_len != 0) {
      xcode(p);
    }
}

#ifdef WIN
void load_modules(char *names) {
    HMODULE mod;
    char *p = strtok(names, ";,");
    
    while (p != NULL) {
      printf ("[ loading %s...", p);
      mod = LoadLibrary(p);
      
      printf ("%s\n", mod==NULL ? "FAILED" : "OK");
      
      p = strtok(NULL, ";,");
    }
}
#endif

/**F*****************************************************************/
void usage (void) {
    printf ("\n  usage: runsc <address> [options]\n");
    printf ("\n  -4            Use IP version 4 (default)");
    printf ("\n  -6            Use IP version 6");
    printf ("\n  -l            Listen mode (required when listening on specific interface)");
    #ifdef WIN
    printf ("\n  -m <dll>      Loads DLL modules. Each one separated by comma or semi-colon");
    #endif
    printf ("\n  -f <file>     Read PIC from <file>");
    printf ("\n  -s <count>    Simulate real process by creating file descriptors");
    printf ("\n  -p <number>   Port number to use (default is %s)", DEFAULT_PORT);
    printf ("\n  -x            Execute PIC (requires -f)");
    printf ("\n\n  Press any key to continue . . .");
    getchar ();
    
    exit (0);
}

/**F*****************************************************************/
char* getparam (int argc, char *argv[], int *i) {
    int n=*i;
    if (argv[n][2] != 0) {
      return &argv[n][2];
    }
    if ((n+1) < argc) {
      *i=n+1;
      return argv[n+1];
    }
    printf ("[ %c%c requires parameter\n", argv[n][0], argv[n][1]);
    exit (0);
}

void parse_args (args_t *p, int argc, char *argv[]) {
    int  i;
    char opt;

    // for each argument
    for (i=1; i<argc; i++)
    {
      // is this option?
      if (argv[i][0]=='-' || argv[i][1]=='/')
      {
        // get option value
        opt=argv[i][1];
        switch (opt)
        {
          case '4':
            p->ai_family=AF_INET;
            break;
          case '6':     // use ipv6 (default is ipv4)
            p->ai_family=AF_INET6;
            break;
          case 'x':     // execute PIC, requires -f
            p->mode=RSC_EXEC;
            break;
          case 'd':     // debug the code
            p->dbg=1;
            break;
          case 'f':     // file
            p->file=getparam(argc, argv, &i);
            break;
          case 'l':     // listen for incoming connections
            p->mode=RSC_SERVER;
            break;
          #ifdef WIN  
          case 'm':     // windows only, loads modules required by shellcode
            p->modules = getparam(argc, argv, &i);
            break;
          #endif          
          case 's':     // create file descriptors before execution
            p->sim=atoi(getparam(argc, argv, &i));
            break;
          case 'p':     // port number
            p->port=getparam(argc, argv, &i);
            p->port_nbr=atoi(p->port);
            break;
          case '?':     // display usage
          case 'h':
            usage ();
            break;
          default:
            printf ("[ unknown option %c\n", opt);
            usage();
            break;
        }
      } else {
        // assume it's hostname or ip
        p->address=argv[i];
        p->mode=RSC_CLIENT;
      }
    }
}

int main (int argc, char *argv[]) {
    args_t args;
    struct stat st;
    
    #ifdef WIN
      // 
      PVOID   OldValue=NULL;
      WSADATA wsa;
      
      //Wow64DisableWow64FsRedirection (&OldValue);
      LoadLibrary("ws2_32");
      LoadLibrary("advapi32");
      
      WSAStartup(MAKEWORD(2,0), &wsa);
    #endif
    
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    memset (&args, 0, sizeof(args));
    
    // set default parameters
    args.address   = NULL;
    args.file      = NULL;
    args.ai_family = AF_INET;
    args.port      = DEFAULT_PORT;
    args.port_nbr  = atoi(args.port);
    args.mode      = -1;
    args.tx_mode   = -1;
    args.sim       = 0;
    args.dbg       = 0;
    
    printf ("\n[ run shellcode v0.2\n");
    
    parse_args(&args, argc, argv);
    
    // check if we have file parameter and it accessible
    if (args.file!=NULL) {
      if (stat (args.file, &st)) {
        printf ("[ unable to access %s\n", args.file);
        return 0;
      }
    }
    
    #ifdef WIN
    if (args.modules != NULL) {
      load_modules(args.modules);
    }
    #endif
    // if mode is executing
    if (args.mode == RSC_EXEC) {
      if (args.file != NULL) {
        xfile(&args);
        return 0;
      } else {
        printf ("\n[ you've used -x without supplying file with -f");
        return 0;
      }
    }
    if (init_network(&args)) {
      // if no file specified, we receive and execute data
      args.tx_mode = (args.file==NULL) ? RSC_RECV : RSC_SEND;
      
      // if mode is -1, we listen for incoming connections
      if (args.mode == -1) {
        args.mode=RSC_SERVER;
      }
      
      // if no file specified, set to receive one
      if (args.tx_mode == -1) {
        args.tx_mode = RSC_RECV;
      }
      
      if (args.mode == RSC_SERVER) {
        ssr (&args);
      } else {
        csr (&args);
      }
    }
    if(args.code_len != 0) {
      free(args.code);
    }
    return 0;
}
