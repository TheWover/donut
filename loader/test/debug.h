
#ifndef DEBUG_H
#define DEBUG_H

#include <windows.h>
#include <dbgeng.h>
#include <stdio.h>

#pragma comment(lib, "dbgeng.lib")

class EventCallbacks : public DebugBaseEventCallbacks {
    public:
      STDMETHOD_(ULONG, AddRef)      (THIS ) { return 1;};
      STDMETHOD_(ULONG, Release)     (THIS ) { return 0;};
      STDMETHOD(Breakpoint)          (THIS_ IN PDEBUG_BREAKPOINT Bp );
      STDMETHOD(ChangeDebuggeeState) (THIS_ IN ULONG Flags, IN ULONG64  Argument );
      STDMETHOD(ChangeEngineState)   (THIS_ IN ULONG Flags, IN ULONG64  Argument );
      STDMETHOD(ChangeSymbolState)   (THIS_ IN ULONG Flags, IN ULONG64  Argument );
      STDMETHOD(CreateThread)        (THIS_ IN ULONG64  Handle, IN ULONG64  DataOffset,IN ULONG64  StartOffset);
      STDMETHOD(Exception)           (THIS_ IN PEXCEPTION_RECORD64 Exception, IN ULONG FirstChance );
      STDMETHOD(ExitProcess)         (THIS_ IN ULONG  ExitCode );
      STDMETHOD(ExitThread)          (THIS_ IN ULONG  ExitCode );
      STDMETHOD(GetInterestMask)     (THIS_ OUT PULONG Mask );
      STDMETHOD(SessionStatus)       (THIS_ IN ULONG Status );
      STDMETHOD(SystemError)         (THIS_ IN ULONG  Error, IN ULONG  Level );
      STDMETHOD(UnloadModule)        (THIS_ IN PCSTR  ImageBaseName, IN ULONG64  BaseOffset );
      STDMETHOD(LoadModule)          (THIS_ IN ULONG64 ImageFileHandle, IN ULONG64 BaseOffset, IN ULONG ModuleSize,  IN PCSTR ModuleName,IN PCSTR ImageName,  IN ULONG CheckSum, IN ULONG TimeDateStamp );
      STDMETHOD(CreateProcess)       ( THIS_ IN ULONG64 ImageFileHandle, IN ULONG64 Handle, IN ULONG64 BaseOffset, IN ULONG ModuleSize, IN PCSTR ModuleName, IN PCSTR ImageName, IN ULONG CheckSum, IN ULONG TimeDateStamp,  IN ULONG64 InitialThreadHandle,   IN ULONG64 ThreadDataOffset,  IN ULONG64 StartOffset );
      
      IDebugClient*        Client;
      IDebugControl*       Control;
};

class StdioOutputCallbacks : public IDebugOutputCallbacks {
    public:
      STDMETHOD(QueryInterface)(THIS_ IN REFIID InterfaceId, OUT PVOID* Interface);
      STDMETHOD_(ULONG, AddRef)(THIS){ return 1; };
      STDMETHOD_(ULONG, Release)(THIS){ return 0; };
      STDMETHOD(Output)(THIS_ IN ULONG Mask, IN PCSTR Text) { fputs(Text, stdout); return S_OK; };
};

class StdioInputCallbacks : public IDebugInputCallbacks {
    public:
      STDMETHOD(QueryInterface)(THIS_ IN REFIID InterfaceId, OUT PVOID* Interface);
      STDMETHOD_(ULONG, AddRef)(THIS){ return 1; };
      STDMETHOD_(ULONG, Release)(THIS) { return 0; };
      STDMETHOD(StartInput)(THIS_ IN ULONG  BufferSize);
      STDMETHOD(EndInput)(THIS_ void) { return S_OK; };
      
      IDebugControl* Control;
};

class Debug {
    public:
      Debug();
      Debug(PSTR CommandLine, ULONG ProcessId);
      ~Debug();
      BOOL Debug::Start(PSTR CommandLine, ULONG ProcessId);
      
      StdioOutputCallbacks OutputCb;
      StdioInputCallbacks  InputCb;
      EventCallbacks       EventCb;
      
      IDebugClient*        Client;
      IDebugControl*       Control;
      IDebugBreakpoint*    Breakpoint;
      bool                 State;
      HRESULT              Status;
};

#endif