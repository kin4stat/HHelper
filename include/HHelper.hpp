#ifndef HOOKHELPER_HPP
#define HOOKHELPER_HPP

#include <cstring>
#include <windows.h>

namespace HHelper {

    enum class HH_Status {
        ERR_OK,
        ERR_NOT_READY,
        ERR_MISSING_TRAMPOLINE,
        ERR_VIRTUAL_ALLOC,
        ERR_INVALIDSIZE,
    };

    enum class CallType {
        JMP,
        CALL,
    };

    class HookHelper {
    public:
        HookHelper(void* originalFunction, unsigned char AdditionalBytesCount, const void* AdditionalBytesInitializer = nullptr, unsigned char AdditionalBytesSize = 0,
            CallType OriginalFunction = CallType::JMP, CallType Trampoline = CallType::JMP)
            : SP(0), error(HH_Status::ERR_OK), InstructionsPointer(nullptr), JMPSize(5) {

            auto TrampolineCallByte = (Trampoline == CallType::JMP) ? 0xE9 : 0xE8;
            auto OriginalCallByte = (OriginalFunction == CallType::JMP) ? 0xE9 : 0xE8;
            push(0xE9); // JMP
            auto jmplong = 0x05 + AdditionalBytesCount + ((Trampoline == CallType::CALL) ? 1 : 0);
            SetBytes(&jmplong, 4); // JMP Distance
            if (AdditionalBytesCount) {
                if (AdditionalBytesInitializer && AdditionalBytesSize) {
                    SetBytes(AdditionalBytesInitializer, AdditionalBytesSize);
                    AdditionalBytesSP = SP;
                    FillBytes(0x90, AdditionalBytesCount - AdditionalBytesSize);
                }
                else {
                    AdditionalBytesSP = SP;
                    FillBytes(0x90, AdditionalBytesCount);
                }
            }
            push(TrampolineCallByte); // JMP
            TrampolineSP = SP;
            FillBytes(0x90, 4); // NOPS for trampoline
            if (Trampoline == CallType::CALL) {
                push(0xC3);
            }
            push(OriginalCallByte); // JMP
            auto rel = reinterpret_cast<unsigned char*>(originalFunction) - 4;
            OriginalFuncSP = SP;
            SetBytes(&rel, 4); // Set Pseudo Relative address;
            if (OriginalFunction == CallType::CALL) {
                push(0xC3);
            }
        }

        HookHelper(void* originalFunction, CallType OriginalFunction = CallType::JMP, CallType Trampoline = CallType::JMP)
            : SP(0), error(HH_Status::ERR_OK), InstructionsPointer(nullptr), JMPSize(2) {
            auto TrampolineCallByte = (Trampoline == CallType::JMP) ? 0xE9 : 0xE8;
            auto OriginalCallByte = (OriginalFunction == CallType::JMP) ? 0xE9 : 0xE8;
            push(0xEB); // JMP Short
            push(0x05); // Distance
            push(TrampolineCallByte); // JMP
            TrampolineSP = SP;
            FillBytes(0x90, 4); // NOPS for trampoline
            if (Trampoline == CallType::CALL) {
                push(0xC3);
            }
            push(OriginalCallByte); // JMP
            auto rel = reinterpret_cast<unsigned char*>(originalFunction) - 4;
            OriginalFuncSP = SP;
            SetBytes(&rel, 4); // Set Pseudo Relative address;
            if (OriginalFunction == CallType::CALL) {
                push(0xC3);
            }
        }

        ~HookHelper() {
            memset(InstructionsPointer, 0x90, JMPSize); // NOP JMP instruction;
        }

        void* GetInstructionPointer() {
            if (InstructionsPointer == nullptr) {
                InstructionsPointer = reinterpret_cast<unsigned char*>(VirtualAlloc(0, SP, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
                if (InstructionsPointer == nullptr) {
                    error = HH_Status::ERR_VIRTUAL_ALLOC;
                    return nullptr;
                }
                unsigned char* newrel = reinterpret_cast<unsigned char*>(GetData<unsigned char*>(OriginalFuncSP) - &InstructionsPointer[OriginalFuncSP]);
                SP = OriginalFuncSP;
                SetBytes(&newrel, 4);
                memcpy(InstructionsPointer, stack, SP); // Set original relative address to executable code;
            }
            error = HH_Status::ERR_OK;
            return InstructionsPointer;
        }

        void SetTrampoline(void* Trampoline) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return;
            }
            unsigned char* tramp = reinterpret_cast<unsigned char*>(reinterpret_cast<unsigned char*>(Trampoline) - &InstructionsPointer[TrampolineSP] - 4);
            memcpy(&InstructionsPointer[TrampolineSP], &tramp, 4); // Set trampoline to executable code;
            error = HH_Status::ERR_OK;
        }

        template <typename DataType>
        void SetAdditionalBytes(unsigned char opcode, DataType& opcodedata) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return;
            }
            if (TrampolineSP - AdditionalBytesSP - 1 - 1 < sizeof(opcodedata)) {// -1 Opcode and -1 JMP or CALL opcode
                error = HH_Status::ERR_INVALIDSIZE;
                return;
            }
            auto OriginalSP = SP;
            SP = AdditionalBytesSP;
            pushToInstructions(opcode);
            AdditionalBytesSP = SP;
            SP = OriginalSP;
            SetAdditionalBytes(opcodedata);
        }

        void SetAdditionalBytes(unsigned char opcode, const void* opcodedata, unsigned char opcodedata_size) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return;
            }
            if (opcodedata_size > TrampolineSP - AdditionalBytesSP - 1 - 1) { // -1 Opcode and -1 JMP or CALL opcode
                error = HH_Status::ERR_INVALIDSIZE;
                return;
            }
            auto OriginalSP = SP;
            SP = AdditionalBytesSP;
            pushToInstructions(opcode);
            AdditionalBytesSP = SP;
            SP = OriginalSP;
            SetAdditionalBytes(opcodedata, opcodedata_size);
        }

        template <typename DataType>
        void SetAdditionalBytes(DataType& opcodedata) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return;
            }
            if (TrampolineSP - AdditionalBytesSP - 1 < sizeof(opcodedata)) { // -1 JMP or CALL opcode
                error = HH_Status::ERR_INVALIDSIZE;
                return;
            }
            auto OriginalSP = SP;
            SP = AdditionalBytesSP;
            SetBytesToInstructions(&opcodedata, sizeof(opcodedata));
            AdditionalBytesSP = SP;
            SP = OriginalSP;
            error = HH_Status::ERR_OK;
        }

        void SetAdditionalBytes(const void* opcodedata, unsigned char opcodedata_size) {
            if (InstructionsPointer == nullptr) {
                error = HH_Status::ERR_NOT_READY;
                return;
            }
            if (TrampolineSP - AdditionalBytesSP - 1 < opcodedata_size) { // -1 JMP or CALL opcode
                error = HH_Status::ERR_INVALIDSIZE;
                return;
            }
            auto OriginalSP = SP;
            SP = AdditionalBytesSP;
            SetBytesToInstructions(opcodedata, opcodedata_size);
            AdditionalBytesSP = SP;
            SP = OriginalSP;
            error = HH_Status::ERR_OK;
        }

        HH_Status GetError() {
            return error;
        }

    private:
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
        unsigned char AdditionalBytesSP;
        unsigned char TrampolineSP;
        unsigned char OriginalFuncSP;
        unsigned char JMPSize;

        unsigned char stack[128];
        unsigned char SP;
        HH_Status error;
    };

} // namespace HookHelper

#endif // HOOKHELPER_HPP