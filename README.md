# HHelper (x86)

A lightweight single header library for easier hooking 

# Examples

Hooks won't crash after unloading the DLL

```cpp
static HookHelper helper(&HookFunction);
MH_CreateHook(functionPointer, helper.GetInstructionPointer(), &Trampoline);
MH_EnableHook(functionPointer);
helper.SetTrampoline(Trampoline);
```

RET opcode will be automatically placed if you choose CALL type

```cpp
WNDPROC m_pWindowProc;

LRESULT __stdcall WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    return CallWindowProcA(m_pWindowProc, hWnd, msg, wParam, lParam);
}
void InstallWndProcHook() {
    const char Pushes[] = { 
        "\xFF\x74\x24\x10" // push [esp + 0x10]
        "\xFF\x74\x24\x10" // push [esp + 0x10]
        "\xFF\x74\x24\x10" // push [esp + 0x10]
        "\xFF\x74\x24\x10" // push [esp + 0x10]
        "\x68" }; // push
    auto push_size = sizeof(Pushes) - 1;
    static HookHelper helper(&WndProcHandler,  push_size + 5, Pushes, push_size, CallType::JMP, CallType::CALL);
    auto HandlerPointer = reinterpret_cast<LONG>(helper.GetInstructionPointer()));
    m_pWindowProc = reinterpret_cast<WNDPROC>(SetWindowLongW(hWnd, GWL_WNDPROC, HandlerPointer);
    helper.SetAdditionalBytes(m_pWindowProc);
    helper.SetTrampoline(GetProcAddress(GetModuleHandleA("user32.dll"), "CallWindowProcA"));
}
```
