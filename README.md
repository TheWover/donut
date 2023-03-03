[![Issues](https://img.shields.io/github/issues/thewover/donut)](https://github.com/TheWover/donut/issues)
[![Contributors](https://img.shields.io/github/contributors/thewover/donut)](https://github.com/TheWover/donut/graphs/contributors)
[![Stars](https://img.shields.io/github/stars/thewover/donut)](https://github.com/TheWover/donut/stargazers)
[![Forks](https://img.shields.io/github/forks/thewover/donut)](https://github.com/TheWover/donut/network/members)
[![License](https://img.shields.io/github/license/thewover/donut)](https://github.com/TheWover/donut/blob/master/LICENSE)
[![Chat](https://img.shields.io/badge/chat-%23donut-orange)](https://bloodhoundgang.herokuapp.com/)
[![Github All Releases](https://img.shields.io/github/downloads/thewover/donut/total.svg)](http://www.somsubhra.com/github-release-stats/?username=thewover&repository=donut) 
[![Twitter URL](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?original_referer=https://github.com/TheWover/donut&text=%23Donut+An+open-source+shellcode+generator+that+supports+in%2Dmemory+execution+of+VBS%2FJS%2FEXE%2FDLL+files:+https://github.com/TheWover/donut)

![Alt text](https://github.com/TheWover/donut/blob/master/img/donut_logo_white.jpg?raw=true "Donut Logo")

<p>Current version: <a href="https://thewover.github.io/TBD/">v1</a></p>

<h2>Table of contents</h2>

<ol>
  <li><a href="#intro">Introduction</a></li>
  <li><a href="#how">How It Works</a></li>
  <li><a href="#build">Building</a></li>
  <li><a href="#usage">Usage</a></li>
  <li><a href="#subproj">Subprojects</a></li>
  <li><a href="#dev">Developing with Donut</a></li>
  <li><a href="#qad">Questions and Discussions</a></li>
  <li><a href="#disclaimer">Disclaimer</a></li>
</ol>

<h2 id="intro">1. Introduction</h2>

<p><strong>Donut</strong> is a position-independent code that enables in-memory execution of VBScript, JScript, EXE, DLL files and dotNET assemblies. A module created by Donut can either be staged from a HTTP server or embedded directly in the loader itself. The module is optionally encrypted using the <a href="https://tinycrypt.wordpress.com/2017/02/20/asmcodes-chaskey-cipher/">Chaskey</a> block cipher and a 128-bit randomly generated key. After the file is loaded and executed in memory, the original reference is erased to deter memory scanners. The generator and loader support the following features:</p>

<ul>
  <li>Compression of input files with aPLib and LZNT1, Xpress, Xpress Huffman via RtlCompressBuffer.</li> 
  <li>Using entropy for API hashes and generation of strings.</li> 
  <li>128-bit symmetric encryption of files.</li>
  <li>Overwriting native PE headers.</li>
  <li>Storing native PEs in MEM_IMAGE memory.</li>
  <li>Patching Antimalware Scan Interface (AMSI) and Windows Lockdown Policy (WLDP).</li>
  <li>Patching Event Tracing for Windows (ETW).</li>
  <li>Patching command line for EXE files.</li>
  <li>Patching exit-related API to avoid termination of host process.</li>
  <li>Multiple output formats: C, Ruby, Python, PowerShell, Base64, C#, Hexadecimal, and UUID string.</li>
</ul>

<p>There are dynamic and static libraries for both Linux and Windows that can be integrated into your own projects. There's also a python module which you can read more about in <a href="https://github.com/TheWover/donut/blob/master/docs/2019-08-21-Python_Extension.md">Building and using the Python extension.</a></p>

<h2 id="how">2. How It Works</h2>

<p>Donut contains individual loaders for each supported file type. For dotNET EXE/DLL assemblies, Donut uses the Unmanaged CLR Hosting API to load the Common Language Runtime. Once the CLR is loaded into the host process, a new Application Domain is created to allow for running Assemblies in disposable AppDomains. When the AppDomain is ready, the dotNET Assembly is loaded via the AppDomain.Load_3 method. Finally, the Entry Point for EXEs or public method for DLLs specified by the user is invoked with any additional parameters. Refer to MSDN for documentation on the <a href=" https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/hosting/clr-hosting-interfaces">Unmanaged CLR Hosting API.</a> For a standalone example of a CLR Host, refer to <a href="https://github.com/TheWover/donut/blob/master/DonutTest/rundotnet.cpp">code here.</a></p>

<p>VBScript and JScript files are executed using the IActiveScript interface. There's also minimal support for some of the methods provided by the Windows Script Host (wscript/cscript). For a standalone example, refer to <a href="https://gist.github.com/odzhan/d18145b9538a3653be2f9a580b53b063">code here.</a> For a more detailed description, read: <a href="https://modexp.wordpress.com/2019/07/21/inmem-exec-script/">In-Memory Execution of JavaScript, VBScript, JScript and XSL</a></p>

<p>Unmanaged or native EXE/DLL files are executed using a custom PE loader with support for Delayed Imports, TLS and patching the command line. Only files with relocation information are supported. Read <a href="https://modexp.wordpress.com/2019/06/24/inmem-exec-dll/">In-Memory Execution of DLL</a> for more information.</p>

<p>The loader can disable AMSI and WLDP to help evade detection of malicious files executed in-memory. For more information, read <a href="https://modexp.wordpress.com/2019/06/03/disable-amsi-wldp-dotnet/">How Red Teams Bypass AMSI and WLDP for .NET Dynamic Code</a>. It also supports decompression of files in memory using aPLib or the RtlDecompressBuffer API. Read <a href="https://modexp.wordpress.com/2019/12/08/shellcode-compression/">Data Compression</a> for more information.</p>

<p>As of v1.0, ETW is also bypassed. Like with AMSI/WLDP, this a modular system that allows you to swap out the default bypass with your own. The default bypass is derived from research by XPN. Read <a href="https://blog.xpnsec.com/hiding-your-dotnet-etw/">Hiding your .NET - ETW</a> for more information.</p>

<p>By default, the loader will overwrite the PE headers of unmanaged PEs (from the base address to `IMAGE_OPTIONAL_HEADER.SizeOfHeaders`). If no decoy module is used (module overloading), then the PE headers will be zeroed. If a decoy module is used, the PE headers of the decoy module will be used to overwrite those of the payload module. This is to deter detection by comparing the PE headers of modules in memory with the file backing them on disk. The user may request that all PE headers be preserved in their original state. This is helpful for scenarios when the payload module needs to access its PE headers, such as when looking up embedded PE resources.</p>

<p>For a detailed walkthrough using the generator and how Donut affects tradecraft, read <a href="https://thewover.github.io/Introducing-Donut/">Donut - Injecting .NET Assemblies as Shellcode</a>. For more information about the loader, read <a href="https://modexp.wordpress.com/2019/05/10/dotnet-loader-shellcode/">Loading .NET Assemblies From Memory</a>.</p>

<p>Those who wish to know more about the internals should refer to <a href="https://github.com/TheWover/donut/blob/master/docs/devnotes.md">Developer notes.</a></p>

<h2 id="build">3. Building</h2>

<p>There are two types of build. If you want to debug Donut, please refer to <a href="https://github.com/TheWover/donut/blob/master/docs/devnotes.md">documentation here</a>. If not, continue reading for the release build.</p>

<h3><strong>Clone</strong></h3>

<p>From a Windows command prompt or Linux terminal, clone the repository.</p>

<pre> 
  git clone http://github.com/thewover/donut.git
</pre>

<p>The next step depends on your operating system and what compiler you decide to use. Currently, the generator and loader template for Donut can be compiled successfully with both Microsoft Visual Studio 2019 and MingGW-64. To use the libraries in your own C/C++ project, please refer to the <a href="https://github.com/TheWover/donut/tree/master/examples">examples provided here.</a></p>

<h4><strong>Windows</strong></h4>

<p>To generate the loader template, dynamic library donut.dll, the static library donut.lib and the generator donut.exe. Start an x64 Microsoft Visual Studio Developer Command Prompt, change to the directory where you cloned the Donut repository and enter the following:</p>

<pre>
  nmake -f Makefile.msvc
</pre>

<p>To do the same, except using MinGW-64 on Windows or Linux, change to the directory where you cloned the Donut repository and enter the following:</p>

<pre>
  make -f Makefile.mingw
</pre>

<h4><strong>Linux</strong></h4>

<p>To generate the dynamic library donut.so, the static library donut.a and the generator donut. Change to the directory where you cloned the Donut repository and simply type make.</p>

<h3>Python Module</h3>

<p>Donut can be installed and used as a Python module. To install from source requires pip for Python3. First, ensure older versions of donut-shellcode are not installed by issuing the following command on Linux terminal or Microsoft Visual Studio command prompt.</p>

<pre>
  pip3 uninstall donut-shellcode
</pre>

<p>After you confirm older versions are no longer installed, issue the following command.</p>

<pre>
  pip3 install .
</pre>

<p>You may also install Donut as a Python module by grabbing it from the PyPi repository.</p>

<pre>
  pip3 install donut-shellcode
</pre>

<p>For more information, please refer to <a href="https://github.com/TheWover/donut/blob/master/docs/2019-08-21-Python_Extension.md">Building and using the Python extension.</a></p>

<h3>Docker</h3>

<p>Building the docker container.</p>

<pre>
  docker build -t donut .
</pre>

<p>Running donut.</p>

<pre>
  docker run -it --rm -v "${PWD}:/workdir" donut -h
</pre>

<h3>Support Tools</h3>

<p>Donut includes several other executables that may be built separately. This include "hash.exe", "encrypt.exe","inject.exe", and "inject_local.exe". The first two are used in shellcode generation. The latter two are provided to assist with testing donut shellcode. "inject.exe" will inject a raw binary file (loader.bin) into a process by its PID or process name. "inject_local.exe" will inject a raw binary file into its own process.</p>

<p>To build these support executables separately you may use the MSVC makefile. For example, to build "inject_local.exe" to test your donut shellcode, you may run.</p>

<pre>
  nmake inject_local -f Makefile.msvc
</pre>

<h3>Releases</h3>

<p>Tags have been provided for each release version of Donut that contain the compiled executables.</p>

<ul>
  <li><a href="https://github.com/TheWover/donut/releases/tag/v0.9.3">v0.9.3, TBD</a></li>
  <li><a href="https://github.com/TheWover/donut/releases/tag/v0.9.2">v0.9.2, Bear Claw</a></li>
  <li><a href="https://github.com/TheWover/donut/releases/tag/v0.9.1">v0.9.1, Apple Fritter</a></li>
  <li><a href="https://github.com/TheWover/donut/releases/tag/v0.9">v0.9.0, Initial Release</a></li>
</ul>

<p>Currently, there are two other generators available.</p>

<ul>
  <li><a href="https://github.com/n1xbyte/donutCS">C# generator by n1xbyte</a></li>
  <li><a href="https://github.com/Binject/go-donut">Go generator by awgh</a></li>
</ul>

<h2 id="usage">4. Usage</h2>

<p>The following table lists switches supported by the command line version of the generator.</p>

<table border="1">
  <tr>
    <th>Switch</th>
    <th>Argument</th>
    <th>Description</th>
  </tr>
  
  <tr>
    <td><strong>-a</strong></td>
    <td><var>arch</var></td>
    <td>Target architecture for loader : 1=x86, 2=amd64, 3=x86+amd64(default).</td>
  </tr>
  
  <tr>
    <td><strong>-b</strong></td>
    <td><var>level</var></td>
    <td>Behavior for bypassing AMSI/WLDP : 1=None, 2=Abort on fail, 3=Continue on fail.(default)</td>
  </tr>

  <tr>
    <td><strong>-k</strong></td>
    <td><var>headers</var></td>
    <td>Preserve PE headers. 1=Overwrite (default), 2=Keep all</td>
  </tr>

  <tr>
    <td><strong>-j</strong></td>
    <td><var>decoy</var></td>
    <td>Optional path of decoy module for Module Overloading.</td>
  </tr>
  
  <tr>
    <td><strong>-c</strong></td>
    <td><var>class</var></td>
    <td>Optional class name. (required for .NET DLL) Can also include namespace: e.g <em>namespace.class</em></td>
  </tr>  
  
  <tr>
    <td><strong>-d</strong></td>
    <td><var>name</var></td>
    <td>AppDomain name to create for .NET. If entropy is enabled, one will be generated randomly.</td>
  </tr>  

  <tr>
    <td><strong>-e</strong></td>
    <td><var>level</var></td>
    <td>Entropy level. 1=None, 2=Generate random names, 3=Generate random names + use symmetric encryption (default)</td>
  </tr>
  
  <tr>
    <td><strong>-f</strong></td>
    <td><var>format</var></td>
    <td>The output format of loader saved to file. 1=Binary (default), 2=Base64, 3=C, 4=Ruby, 5=Python, 6=PowerShell, 7=C#, 8=Hexadecimal</td>
  </tr>
  
  <tr>
    <td><strong>-m</strong></td>
    <td><var>name</var></td>
    <td>Optional method or function for DLL. (a method is required for .NET DLL)</td>
  </tr>
  
  <tr>
    <td><strong>-n</strong></td>
    <td><var>name</var></td>
    <td>Module name for HTTP staging. If entropy is enabled, one is generated randomly.</td>
  </tr>
  
  <tr>
    <td><strong>-o</strong></td>
    <td><var>path</var></td>
    <td>Specifies where Donut should save the loader. Default is "loader.bin" in the current directory.</td>
  </tr>

  <tr>
    <td><strong>-p</strong></td>
    <td><var>parameters</var></td>
    <td>Optional parameters/command line inside quotations for DLL method/function or EXE.</td>
  </tr>
  
  <tr>
    <td><strong>-r</strong></td>
    <td><var>version</var></td>
    <td>CLR runtime version. MetaHeader used by default or v4.0.30319 if none available.</td>
  </tr>
  
  <tr>
    <td><strong>-s</strong></td>
    <td><var>server</var></td>
    <td>URL for the HTTP server that will host a Donut module. Credentials may be provided in the following format: <pre>https://username:password@192.168.0.1/</pre></td>
  </tr>

  <tr>
    <td><strong>-t</strong></td>
    <td></td>
    <td>Run the entrypoint of an unmanaged/native EXE as a thread and wait for thread to end.</td>
  </tr>
  
  <tr>
    <td><strong>-w</strong></td>
    <td></td>
    <td>Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)</td>
  </tr>
  
  <tr>
    <td><strong>-x</strong></td>
    <td><var>option</var></td>
    <td>Determines how the loader should exit. 1=exit thread (default), 2=exit process, 3=Do not exit or cleanup and block indefinitely</td>
  </tr>

  <tr>
    <td><strong>-y</strong></td>
    <td><var>addr</var></td>
    <td>Creates a new thread for the loader and continues execution at an address that is an offset relative to the host process's executable. The value provided is the offset. This option supports loaders that wish to resume execution of the host process after donut completes execution.</td>
  </tr>

  <tr>
    <td><strong>-z</strong></td>
    <td><var>engine</var></td>
    <td>Pack/Compress the input file. 1=None, 2=aPLib, 3=LZNT1, 4=Xpress, 5=Xpress Huffman. Currently, the last three are only supported on Windows.</td>
  </tr>
</table>

<h3 id="requirements">Payload Requirements</h2>

<p>There are some specific requirements that your payload must meet in order for Donut to successfully load it.</p>

<h3 id="requirements-dotnet">.NET Assemblies</h2>

<ul>
  <li>The entry point method must only take strings as arguments, or take no arguments.</li>
  <li>The entry point method must be marked as public and static.</li>
  <li>The class containing the entry point method must be marked as public.</li>
  <li>The Assembly must NOT be a Mixed Assembly (contain both managed and native code).</li>
  <li>As such, the Assembly must NOT contain any Unmanaged Exports.</li>
</ul>

<h3 id="requirements-native">Native EXE/DLL</h2>

<ul>
  <li>Binaries built with Cygwin are unsupported.</li>
</ul>

<p>Cygwin executables use initialization routines that expect the host process to be running from disk. If executing from memory, the host process will likely crash.</p>

<h3 id="requirements-dotnet">Unmanaged DLLs</h2>

<ul>
  <li>A user-specified entry point method must only take a string as an argument, or take no arguments. We have provided an <a href="https://github.com/TheWover/donut/blob/master/DonutTest/dlltest.c/">example</a>.</li>
</ul>

<h2 id="subproj">5. Subprojects</h2>

<p>There are four companion projects provided with donut:</p>

<table border="1">
  <tr>
    <th>Tool</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>DemoCreateProcess</td>
    <td>A sample .NET Assembly to use in testing. Takes two command-line parameters that each specify a program to execute.</td>
  </tr>
  <tr>
    <td>DonutTest</td>
    <td>A simple C# shellcode injector to use in testing donut. The shellcode must be base64 encoded and copied in as a string.</td>
  </tr>
  <tr>
    <td>ModuleMonitor</td>
    <td>A proof-of-concept tool that detects CLR injection as it is done by tools such as Donut and Cobalt Strike's execute-assembly.</td>
  </tr>
  <tr>
    <td>ProcessManager</td>
    <td>A Process Discovery tool that offensive operators may use to determine what to inject into and defensive operators may use to determine what is running, what properties those processes have, and whether or not they have the CLR loaded. </td>
  </tr>
</table>

<h2 id="dev">6. Developing with Donut</h2>

<p>You may want to add support for more types of payloads, change our feature set, or integrate Donut into your existing tooling. We have provided <a href="https://github.com/TheWover/donut/blob/master/docs/devnotes.md">developer documentation</a>. Additional features are left as exercises to the reader. Our suggestions:</p>

<ul>
  <li>Add environmental keying.</li>
  <li>Make Donut polymorphic by obfuscating the loader every time shellcode is generated.</li>
  <li>Integrate Donut as a module into your favorite RAT/C2 Framework.</li>
</ul>

<h2 id="qad">7. Questions and Discussion</h2>

<p>If you have any questions or comments about Donut. Join the #Donut channel in the <a href="https://bloodhoundgang.herokuapp.com/">BloodHound Gang Slack</a></p>

<h2 id="disclaimer">8. Disclaimer</h2>

<p>We are not responsible for any misuse of this software or technique. Donut is provided as a demonstration of CLR Injection and in-memory loading through shellcode in order to provide red teamers a way to emulate adversaries and defenders a frame of reference for building analytics and mitigations. This inevitably runs the risk of malware authors and threat actors misusing it. However, we believe that the net benefit outweighs the risk. Hopefully that is correct. In the event EDR or AV products are capable of detecting Donut via signatures or behavioral patterns, we will not update Donut to counter signatures or detection methods. To avoid being offended, please do not ask.</p>
