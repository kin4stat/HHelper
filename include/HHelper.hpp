#ifndef HOOKHELPER_HPP
#define HOOKHELPER_HPP

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <cstring> // Memory operations
#include <windows.h>
#if defined(_MSC_VER) || defined(__MINGW32__)
#include <stdlib.h>
#define ALIGNED_ALLOC(a, s) _aligned_malloc(s, a)
#else
#include <cstdlib>
#define ALIGNED_ALLOC(a, s) std::aligned_alloc(a, s)
#endif

namespace HHelper {

    // Thanks memir
    namespace func_type_traits
    {
        //enum class cconv
        //{
        //    cthiscall, ccdecl, cstdcall, cfastcall
        //};
        //template <typename>
        //struct function_convention {};
        //template <typename Ret, typename... Args>
        //struct function_convention<Ret(__stdcall*) (Args...)>
        //{
        //    static constexpr cconv value = cconv::cstdcall;
        //};
        //template <typename Ret, typename... Args>
        //struct function_convention<Ret(__cdecl*) (Args...)>
        //{
        //    static constexpr cconv value = cconv::ccdecl;
        //};
        //template <typename Ret, typename Class, typename... Args>
        //struct function_convention<Ret(Class::*)(Args...)>
        //{
        //    static constexpr cconv value = cconv::cthiscall;
        //};
        //template <typename Ret, typename... Args>
        //struct function_convention<Ret(__fastcall*) (Args...)>
        //{
        //    static constexpr cconv value = cconv::cfastcall;
        //};
        //template <typename Ret, typename... Args>
        //struct function_convention<Ret(__thiscall*) (Args...)>
        //{
        //    static constexpr cconv value = cconv::cthiscall;
        //};
        //template <typename Func>
        //constexpr cconv function_convention_v = function_convention<Func>::value;

        template <typename>
        struct function_args_count {};
        template <typename Ret, typename... Args>
        struct function_args_count<Ret(__stdcall*) (Args...)>
        {
            static constexpr int value = sizeof...(Args);
        };
        template <typename Ret, typename... Args>
        struct function_args_count<Ret(__cdecl*) (Args...)>
        {
            static constexpr int value = sizeof...(Args);
        };
        template <typename Ret, typename Class, typename... Args>
        struct function_args_count<Ret(Class::*)(Args...)>
        {
            static constexpr int value = sizeof...(Args) - 1;
        };
        template <typename Ret, typename... Args>
        struct function_args_count<Ret(__fastcall*) (Args...)>
        {
            static constexpr int value = sizeof...(Args) - 2;
        };
        template <typename Ret, typename... Args>
        struct function_args_count<Ret(__thiscall*) (Args...)>
        {
            static constexpr int value = sizeof...(Args) - 1;
        };

        template <typename Func>
        constexpr int function_args_count_v = function_args_count<Func>::value;
    };

    enum class HH_Status {
        ERR_OK,
        ERR_NOT_READY,
        ERR_MISSING_TRAMPOLINE,
        ERR_ALLOC,
        ERR_INVALIDSIZE,
    };

    enum class CallType {
        JMP,
        CALL,
    };

    class HookHelper {
    public:
        /**
         * @param originalFunction pointer to originalFunction
         * @param OriginalFunctionCallType call type of originalFunction
         * @param TrampolineCallType call type of Trampoline function
         */
        HookHelper(void* originalFunction, CallType OriginalFunctionCallType = CallType::JMP, CallType TrampolineCallType = CallType::JMP)
            : SP(0), BeforeCallSP(5), error(HH_Status::ERR_OK), InstructionsPointer(nullptr) {
            memset(&stack[0], Opcode::INT3, sizeof(stack)); // Safety
            auto TrampolineCallByte = (TrampolineCallType == CallType::JMP) ? Opcode::JMP : Opcode::CALL;
            auto OriginalCallByte = (OriginalFunctionCallType == CallType::JMP) ? Opcode::JMP : Opcode::CALL;
            push(Opcode::JMP); // JMP Short
            int jmpsize = 0x05 + ((TrampolineCallType == CallType::CALL) ? 1 : 0);
            SetBytes(&jmpsize, 4);
            BeforeCallSP = SP;
            TrampolineSP = SP;
            push(TrampolineCallByte); // JMP
            FillBytes(Opcode::NOP, 4); // NOPS for trampoline
            if (TrampolineCallType == CallType::CALL) {
                push(Opcode::RET);
            }
            OriginalFunctionCallSP = SP;
            push(OriginalCallByte); // JMP
            auto rel = reinterpret_cast<unsigned char*>(originalFunction) - 4;
            SetBytes(&rel, 4); // Set Pseudo Relative address;
            if (OriginalFunctionCallType == CallType::CALL) {
                push(Opcode::RET);
            }
        }

        ~HookHelper() {
            memset(InstructionsPointer, 0x90, 5); // NOP JMP instruction;
            FlushInstructionCache(GetCurrentProcess(), InstructionsPointer, 5); // Just in case
        }

        /**
         * @brief Used to get executable instructions pointer
         *
         * @return pointer to instructions
         *         returns nullptr if error occured. Use GetLastError to get error code
         */
        void* GetInstructionPointer() {
            if (InstructionsPointer == nullptr) {
                InstructionsPointer = reinterpret_cast<unsigned char*>(ALIGNED_ALLOC(1024, sizeof(stack)));
                {
                    DWORD oldProt;
                    VirtualProtect(InstructionsPointer, sizeof(stack), PAGE_EXECUTE_READWRITE, &oldProt);
                }
                if (InstructionsPointer == nullptr) {
                    error = HH_Status::ERR_ALLOC;
                    return nullptr;
                }
                unsigned char* newrel = reinterpret_cast<unsigned char*>(GetData<unsigned char*>(OriginalFunctionCallSP + 1) - &InstructionsPointer[OriginalFunctionCallSP + 1]);
                SP = OriginalFunctionCallSP + 1;
                SetBytes(&newrel, 4);
                if (SetInstructionsFromStack(-1) == false) {
                    return nullptr;
                }
            }
            error = HH_Status::ERR_OK;
            return InstructionsPointer;
        }

        /**
         * @brief Sets trampoline to instructions pointer
         *
         * @tparam Type of the trampoline function
         * @param Trampoline pointer to trampoline
         * @param function prototype of the function
         *                 used to determine trampoline calling convention and argument count
         * @return true if function succeeds
         * @return false if function fails. Use GetLastError to get error code
         */
        template <typename FunctionType>
        bool SetTrampoline(void* Trampoline, FunctionType function, int manual_args_count = 0) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return false;
            }
            //auto convention = func_type_traits::function_convention_v<decltype(function)>;
            auto argument_count = func_type_traits::function_args_count_v<decltype(function)> - manual_args_count;
            if (argument_count <= 0) {
                return SetTrampoline(Trampoline);
            }
            auto push_offset = argument_count * 4;
            char instruction[]{ '\xFF', '\xB4', '\x24', '\x00', '\x00', '\x00', '\x00'};
            auto instruction_size = 7;
            if (push_offset >= 0x80) { // idk why but lets handle functions with 32+ arguments
                std::memcpy(&instruction[3], &push_offset, 4);
            }
            else {
                instruction[1] = 0x74;
                instruction[3] = static_cast<unsigned char>(push_offset);
                instruction_size = 4;
            }
            AllocateStackMemory(instruction_size * argument_count, TrampolineSP);
            auto original_sp = SP; SP = TrampolineSP;
            for (auto i = 0; i < argument_count; i++) {
                SetBytes(instruction, instruction_size);
            }
            TrampolineSP = SP; SP = original_sp;
            {
                OriginalFunctionCallSP += instruction_size * argument_count;
                RecalculateStackJmpSize();
                RecalculateRelatives(instruction_size * argument_count);
            }
            error = HH_Status::ERR_OK;
            return SetTrampoline(Trampoline);
        }

        /**
         * @brief Sets trampoline to instructions pointer
         *
         * @param Trampoline pointer to trampoline
         * @return true if function succeeds
         * @return false if function fails. Use GetLastError to get error code
         */
        bool SetTrampoline(void* Trampoline) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return false;
            }
            auto tramp = reinterpret_cast<unsigned char*>(Trampoline) - &InstructionsPointer[TrampolineSP] - 5;
            auto original_sp = SP; SP = TrampolineSP + 1;
            SetBytes(&tramp, 4);
            SP = original_sp;
            if (SetInstructionsFromStack(-1) == false) {
                error = HH_Status::ERR_NOT_READY;
                return false;
            }
            error = HH_Status::ERR_OK;
            return true;
        }

        /**
         * @brief Pushes data right before trampoline call
         *
         * @param data user-data
         * @return true if function succeeds
         * @return false if function fails. Use GetLastError to get error code
         */
        template <typename DataType>
        bool PushBytesRightBeforeCall(DataType data) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return false;
            }
            AllocateStackMemory(sizeof(data), TrampolineSP);
            
            auto original_sp = SP; SP = TrampolineSP;
            SetBytes(&data, sizeof(data));
            TrampolineSP = SP; SP = original_sp;
            {
                OriginalFunctionCallSP += sizeof(data);
                RecalculateStackJmpSize();
                RecalculateRelatives(sizeof(data));
            }
            error = HH_Status::ERR_OK;
            return SetInstructionsFromStack(-1);
        }
        /**
         * @brief Pushes data right before trampoline call
         *
         * @param data pointer to user-data
         * @param data_size size of user-data
         * @return true if function succeeds
         * @return false if function fails. Use GetLastError to get error code
         */
        bool PushBytesRightBeforeCall(const void* data, unsigned char data_size) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return false;
            }
            AllocateStackMemory(data_size, TrampolineSP);
            auto original_sp = SP; SP = TrampolineSP;
            SetBytes(data, data_size);
            TrampolineSP = SP; SP = original_sp;
            {
                OriginalFunctionCallSP += data_size;
                RecalculateStackJmpSize();
                RecalculateRelatives(data_size);
            }
            error = HH_Status::ERR_OK;
            return SetInstructionsFromStack(-1);
        }
        /**
         * @brief Pushes user-data before call. The user-data may not be located before the call.
         *        Use PushBytesBeforeCall for guaranteed placement before the call
         *
         * @param data user-data
         * @return true if function succeeds
         * @return false if function fails. Use GetLastError to get error code
         */
        template <typename DataType>
        bool PushBytesBeforeCall(DataType data) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return false;
            }
            AllocateStackMemory(sizeof(data), BeforeCallSP);
            
            auto original_sp = SP; SP = BeforeCallSP;
            SetBytes(&data, sizeof(data));
            BeforeCallSP = SP; SP = original_sp;
            {
                OriginalFunctionCallSP += sizeof(data);
                TrampolineSP += sizeof(data);
                RecalculateStackJmpSize();
                RecalculateRelatives(sizeof(data));
            }
            error = HH_Status::ERR_OK;
            return SetInstructionsFromStack(-1);
        }
        /**
         * @brief Pushes user-data before call. The user-data may not be located before the call.
         *        Use PushBytesBeforeCall for guaranteed placement before the call
         *
         * @param data pointer to user-data
         * @param data_size size of user-data
         * @return true if function succeeds
         * @return false if function fails. Use GetLastError to get error code
         */
        bool PushBytesBeforeCall(const void* data, unsigned char data_size) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return false;
            }
            AllocateStackMemory(data_size, BeforeCallSP);
            auto original_sp = SP; SP = BeforeCallSP;
            SetBytes(data, data_size);
            BeforeCallSP = SP; SP = original_sp;
            {
                OriginalFunctionCallSP += data_size;
                TrampolineSP += data_size;
                RecalculateStackJmpSize();;
                RecalculateRelatives(data_size);
            }
            error = HH_Status::ERR_OK;
            return SetInstructionsFromStack(-1);
        }

        /**
         * @brief Get last error
         *
         * @return HH_Status
         */
        HH_Status GetLastError() {
            return error;
        }

    private:
        enum Opcode {
            NOP = 0x90,
            RET = 0xC3,
            INT3 = 0xCC,
            CALL = 0xE8,
            JMP = 0xE9,
        };

        bool SetInstructionsFromStack(unsigned char size) {
            if (InstructionsPointer == nullptr) { return false; error = HH_Status::ERR_NOT_READY; }
            if (size == -1) size = sizeof(stack);
            std::memcpy(InstructionsPointer, &stack[0], size);
            FlushInstructionCache(GetCurrentProcess(), InstructionsPointer, size); // Just in case
            return true;
        }

        void AllocateStackMemory(unsigned char size, unsigned char SPToAlloc) {
            std::memmove(&stack[SPToAlloc + size], &stack[SPToAlloc], OriginalFunctionCallSP - SPToAlloc + 5);
        }

        void push(const unsigned char byte) {
            stack[SP] = byte; SP++;
        }

        void SetBytes(const void* bytes, unsigned char size) {
            std::memcpy(&stack[SP], bytes, size); SP += size;
        }

        void pushToInstructions(const unsigned char byte) {
            InstructionsPointer[SP] = byte; SP++;
        }

        void SetBytesToInstructions(const void* bytes, unsigned char size) {
            std::memcpy(&InstructionsPointer[SP], bytes, size); SP += size;
        }

        void FillBytes(const unsigned char byte, unsigned char size) {
            std::memset(&stack[SP], byte, size); SP += size;
        }

        void RecalculateStackJmpSize() {
            *reinterpret_cast<size_t*>(&stack[1]) = OriginalFunctionCallSP - 5;
        }

        void RecalculateRelatives(unsigned char offset) {
            *reinterpret_cast<size_t*>(&stack[TrampolineSP + 1]) -= offset;
            *reinterpret_cast<size_t*>(&stack[OriginalFunctionCallSP + 1]) -= offset;
        }

        void RecalculateJmpSize() {
            *reinterpret_cast<size_t*>(&InstructionsPointer[1]) = OriginalFunctionCallSP - 5;
        }

        // returns real pointer
        unsigned char* GetStackPointer() {
            return &stack[SP];
        }

        // returns real pointer
        unsigned char* GetStackPointerForSP(unsigned char RSP) {
            return &stack[RSP];
        }

        template <typename DataType>
        DataType GetData(unsigned char SP) {
            return *reinterpret_cast<DataType*>(&stack[SP]);
        }

        unsigned char* InstructionsPointer;
        unsigned char TrampolineSP;
        unsigned char BeforeCallSP;
        unsigned char OriginalFunctionCallSP;

        unsigned char stack[128];
        unsigned char SP;
        HH_Status error;
    };

} // namespace HookHelper

#endif // HOOKHELPER_HPP
