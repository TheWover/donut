
// example of using the windows debugger engine from console
// derived from code by the blabberer

#include "debug.h"

// ##################### Debug class ########################
Debug::Debug() {
    Client     = NULL;
    Control    = NULL;
    Breakpoint = NULL;
    
    // create instance of IDebugClient
    Status = DebugCreate(__uuidof(IDebugClient), (void**)&Client);
    if(Status == S_OK) {
      // obtain IDebugControl interface
      Status = Client->QueryInterface(__uuidof(IDebugControl), (void**)&Control);
      if(Status == S_OK) {
        // setup callbacks for console I/O
        Client->SetOutputCallbacks(&OutputCb);
        Client->SetInputCallbacks(&InputCb);
        InputCb.Control = Control;
        
        Client->SetEventCallbacks(&EventCb);
        EventCb.Control = Control;
      }
    }
}

// create new process or attach to existing one
// CommandLine should be set to NULL if attaching
Debug::Debug(PSTR CommandLine, ULONG ProcessId) {
    Debug();
    Start(CommandLine, ProcessId);
}

Debug::~Debug() {
    if (Control != NULL) {
      Control->Release();
      Control = NULL;
    }
    if (Client != NULL) {
      Client->EndSession(DEBUG_END_PASSIVE);
      Client->Release();
      Client = NULL;
    }
}

BOOL Debug::Start(PSTR CommandLine, ULONG ProcessId) {
    ULONG AttachFlags = DEBUG_ATTACH_NONINVASIVE | DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND;
    ULONG CreateFlags = DEBUG_ONLY_THIS_PROCESS;
    
    Status = Client->CreateProcessAndAttach(0, CommandLine, CreateFlags, ProcessId, AttachFlags);
    return Status == S_OK;
}

// ##################### IDebugOutputCallbacks ########################
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/dbgeng/nn-dbgeng-idebugoutputcallbacks
STDMETHODIMP StdioOutputCallbacks::QueryInterface(THIS_ IN REFIID InterfaceId, OUT PVOID* Interface) {
    *Interface = NULL;
    
    if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
        IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacks))) {
      *Interface = (IDebugOutputCallbacks *)this;
      AddRef();
      return S_OK;
    } else {
      return E_NOINTERFACE;
    }
}

// ##################### IDebugInputCallbacks ########################
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/dbgeng/nn-dbgeng-idebuginputcallbacks
STDMETHODIMP StdioInputCallbacks::QueryInterface( THIS_ IN REFIID InterfaceId, OUT PVOID* Interface) {
    *Interface = NULL;
    
    if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
        IsEqualIID(InterfaceId, __uuidof(IDebugInputCallbacks))) {
      *Interface = (IDebugInputCallbacks *)this;
      AddRef();
      return S_OK;
    } else {
      return E_NOINTERFACE;
    }
}

STDMETHODIMP StdioInputCallbacks::StartInput(THIS_ IN ULONG BufferSize) {
    char *Buffer;
    
    Buffer = (char *)calloc(1, BufferSize+8);
    fgets(Buffer, BufferSize, stdin);
    Control->ReturnInput(Buffer);
    free(Buffer);
    
    return S_OK;
}

// ##################### DebugBaseEventCallbacks ########################
STDMETHODIMP EventCallbacks::Breakpoint( THIS_ IN PDEBUG_BREAKPOINT Bp ) {
    return DEBUG_STATUS_BREAK;
}

STDMETHODIMP EventCallbacks::CreateProcess(THIS_ IN ULONG64 ImageFileHandle, IN ULONG64 Handle, 
       IN ULONG64 BaseOffset,IN ULONG ModuleSize,IN PCSTR ModuleName,IN PCSTR ImageName, 
       IN ULONG CheckSum, IN ULONG TimeDateStamp,IN ULONG64 InitialThreadHandle, 
       IN ULONG64 ThreadDataOffset,  IN ULONG64 StartOffset 
       )
{
    HRESULT           Status;
    IDebugBreakpoint* Breakpoint;
    
    Status = Control->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &Breakpoint);
    if(Status == S_OK) {
      Status = Breakpoint->SetOffset(StartOffset);
      if(Status == S_OK) {
        Status = Breakpoint->SetFlags(DEBUG_BREAKPOINT_ENABLED);
      }
    }
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::CreateThread(THIS_ IN ULONG64 Handle, IN ULONG64 DataOffset, IN ULONG64 StartOffset) {
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::Exception( THIS_ IN PEXCEPTION_RECORD64 Exception, IN ULONG FirstChance ) {
    return DEBUG_STATUS_BREAK;
} 

STDMETHODIMP EventCallbacks::ExitProcess (THIS_ IN ULONG  ExitCode ) {
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::ExitThread (THIS_ IN ULONG  ExitCode ) {
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::GetInterestMask( THIS_ OUT PULONG Mask ) {
    *Mask =
          DEBUG_EVENT_BREAKPOINT |
          DEBUG_EVENT_EXCEPTION |
          DEBUG_EVENT_CREATE_THREAD |
          DEBUG_EVENT_EXIT_THREAD |
          DEBUG_EVENT_CREATE_PROCESS |
          DEBUG_EVENT_EXIT_PROCESS |
          DEBUG_EVENT_LOAD_MODULE |
          DEBUG_EVENT_UNLOAD_MODULE |
          DEBUG_EVENT_SYSTEM_ERROR |
          DEBUG_EVENT_SESSION_STATUS |
          DEBUG_EVENT_CHANGE_DEBUGGEE_STATE |
          DEBUG_EVENT_CHANGE_ENGINE_STATE |
          DEBUG_EVENT_CHANGE_SYMBOL_STATE;
    return S_OK;
}

STDMETHODIMP EventCallbacks::LoadModule( THIS_ IN ULONG64 ImageFileHandle, IN ULONG64 BaseOffset, 
       IN ULONG ModuleSize,IN PCSTR ModuleName, IN PCSTR ImageName, IN ULONG CheckSum, IN ULONG TimeDateStamp ) {
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::SystemError( THIS_ IN ULONG  Error, IN ULONG  Level ) {
    return DEBUG_STATUS_BREAK;
}

STDMETHODIMP EventCallbacks::UnloadModule( THIS_ IN PCSTR  ImageBaseName, IN ULONG64  BaseOffset ) {
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::SessionStatus( THIS_ IN ULONG SessionStatus ) {
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::ChangeDebuggeeState( THIS_ IN ULONG Flags, IN ULONG64 Argument ) {
    //State = 1;
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::ChangeEngineState( THIS_ IN ULONG Flags, IN ULONG64 Argument ) {
    return DEBUG_STATUS_NO_CHANGE;
}

STDMETHODIMP EventCallbacks::ChangeSymbolState( THIS_ IN ULONG Flags, IN ULONG64 Argument ) {
    return DEBUG_STATUS_NO_CHANGE;
}
