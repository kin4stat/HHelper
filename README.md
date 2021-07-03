# HHelper

A lightweight single header library for easier hooking 

# Examples

Hooks won't crash after unloading the DLL

```cpp
static HookHelper helper(&HookFunction);
MH_CreateHook(functionPointer, helper.GetInstructionPointer(), &Trampoline);
MH_EnableHook(functionPointer);
helper.SetTrampoline(Trampoline);
```

```cpp
WNDPROC m_pWindowProc;

LRESULT __stdcall WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    return CallWindowProcA(m_pWindowProc, hWnd, msg, wParam, lParam);
}
void InstallWndProcHook() {
    /* 
    push [esp + 0x10] ; x4
    push *dword*
    */
    const char Pushes[] = "\xFF\x74\x24\x10" "\xFF\x74\x24\x10" "\xFF\x74\x24\x10" "\xFF\x74\x24\x10" "\x68";
    auto push_size = sizeof(Pushes) - 1;
    static HookHelper helper(&WndProcHandler,  push_size + 5, Pushes, push_size, CallType::JMP, CallType::CALL);
    m_pWindowProc = reinterpret_cast<WNDPROC>(SetWindowLongW(hWnd, GWL_WNDPROC, reinterpret_cast<LONG>(helper.GetInstructionPointer())));
    helper.SetAdditionalBytes(m_pWindowProc);
    helper.SetTrampoline(GetProcAddress(GetModuleHandleA("user32.dll"), "CallWindowProcA"));
}
```