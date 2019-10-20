
#include "debug.h"

Debug *g_Debug;

BOOL WINAPI HandlerRoutine(DWORD dwCtrlType) {
    switch (dwCtrlType) {
      case CTRL_C_EVENT:
        g_Debug->Control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
        return TRUE;
      case CTRL_BREAK_EVENT:
        g_Debug->Control->SetInterrupt(DEBUG_INTERRUPT_ACTIVE);
        return TRUE;
      default:
        return FALSE;
    }
}

VOID DebugSession(VOID) {
    IDebugControl *Control = g_Debug->Control;
    HRESULT       Status;
    ULONG         InputSize, ExecStatus;
    char          input[256];
    
    Status = Control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);

    for(;;) {
      if((Control->GetExecutionStatus(&ExecStatus)) != S_OK) break;
      
      if(ExecStatus == DEBUG_STATUS_NO_DEBUGGEE) break;
      
      if(ExecStatus == DEBUG_STATUS_GO          ||
         ExecStatus == DEBUG_STATUS_STEP_OVER   ||
         ExecStatus == DEBUG_STATUS_STEP_INTO   ||
         ExecStatus == DEBUG_STATUS_STEP_BRANCH) {
        
        Status = Control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
        if(Status == E_UNEXPECTED) break;
        continue;
      }
      Control->OutputCurrentState(DEBUG_OUTCTL_THIS_CLIENT, DEBUG_CURRENT_DEFAULT);
      Control->OutputPrompt(DEBUG_OUTCTL_THIS_CLIENT, NULL);
      Control->Input(input, sizeof(input) - 1, &InputSize);
      if(InputSize == 0) continue;
      Control->Execute(DEBUG_OUTCTL_THIS_CLIENT, input, DEBUG_EXECUTE_DEFAULT);
    }
}

int main(int argc, char *argv[]) {
    PSTR  CommandLine = NULL;
    ULONG ProcessId   = 0;
    
    if(argc != 2) {
      printf("usage: test <ProcessId | CommandLine>\n");
      return 0;
    }
    ProcessId = strtoul(argv[1], NULL, 10);
    if(ProcessId == 0) {
      CommandLine = argv[1];
    }
    // instantiate Debug class
    g_Debug = new Debug();
    
    if(TRUE) { //g_Debug->ok()) {
      SetConsoleCtrlHandler(HandlerRoutine, TRUE);
      
      if(g_Debug->Start(CommandLine, ProcessId)) {
        
        DebugSession();
      }
      
      SetConsoleCtrlHandler(HandlerRoutine, FALSE);
    }
    return 0;
}
