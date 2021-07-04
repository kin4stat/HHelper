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
    static HookHelper helper(&WndProcHandler, CallType::JMP, CallType::CALL);
    m_pWindowProc = reinterpret_cast<WNDPROC>(SetWindowLongW(hWnd, GWL_WNDPROC, reinterpret_cast<LONG>(helper.GetInstructionPointer())));
    helper.SetTrampoline(GetProcAddress(GetModuleHandleA("user32.dll"), "CallWindowProcA"), CallWindowProcA, 1);
    helper.PushBytesRightBeforeCall('\x68'); // Opcode::PUSH
    helper.PushBytesRightBeforeCall(m_pWindowProc);
}
```
```
Output:

jmp 01C42C0A
jmp 01910FE0
jmp ASIPlugin.asi+11168
```

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
    static HookHelper helper(&WndProcHandler, CallType::JMP, CallType::CALL);
    m_pWindowProc = reinterpret_cast<WNDPROC>(SetWindowLongW(**reinterpret_cast<HWND**>(0xC17054), GWL_WNDPROC, reinterpret_cast<LONG>(helper.GetInstructionPointer())));
    helper.SetTrampoline(GetProcAddress(GetModuleHandleA("user32.dll"), "CallWindowProcA"));
    helper.PushBytesBeforeCall(Pushes, push_size);
    helper.PushBytesBeforeCall(m_pWindowProc);
}
```
```
Output:

jmp 132EC420
push [esp+10]
push [esp+10]
push [esp+10]
push [esp+10]
push ___mainthing.asi+2430
call USER32.CallWindowProcA
ret 
jmp ASIPlugin.asi+113E8
```