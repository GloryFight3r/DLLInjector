#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <wchar.h>

#pragma region Globals

const wchar_t* targetProcess = L"TestingHooks.exe";

DWORD GetProcess(const wchar_t* str) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    DWORD result = 0;

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return(NULL);
    }
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);

    if (Process32First(hSnapshot, &procEntry)) {
        do {
            if (!wcscmp(procEntry.szExeFile, str)) {
                result = procEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &procEntry));
    }

    CloseHandle(hSnapshot);
    return result;
}

BOOL WIN32InjectDllToProcesS(DWORD dwProcessId, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, dwProcessId);
    std::cout << hProcess << std::endl;
    if (hProcess) {
        //std::cout << "DASDAS" << std::endl;
        LPVOID lpLoadLibAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (lpLoadLibAddress == NULL) {
            throw std::runtime_error("GetProcAddress");
        }

        LPVOID lpLoadLocation = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (lpLoadLocation == NULL) {
            throw std::runtime_error("VirtualAllocEx");
        }

        if (WriteProcessMemory(hProcess, lpLoadLocation, (LPVOID)dllPath, strlen(dllPath), NULL)) {
            std::cout << "Memory written at: 0x" << std::hex << lpLoadLocation << std::endl;
        }
        else {
            
            throw std::runtime_error("WriteProcessMemory");
        }

        //LPTHREAD_START_ROUTINE thread = (LPTHREAD_START_ROUTINE)system("C:\\Users\\Boruku\\Documents\\C++\\ReadMemory\\Debug\\ReadMemory.exe");
        //std::cout << thread << " " << lpLoadLibAddress << std::endl;
        HANDLE hRemoteThreader = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpLoadLibAddress, lpLoadLocation, NULL, NULL);
        //HANDLE hRemoteThreader = CreateRemoteThread(hProcess, NULL, NULL, thread, lpLoadLocation, NULL, NULL);
        //WaitForSingleObject(hRemoteThreader, INFINITE);
        VirtualFreeEx(hProcess, lpLoadLocation, strlen(dllPath), MEM_RELEASE);

        //std::cout << hRemoteThreader << std::endl;

        CloseHandle(hRemoteThreader);
        CloseHandle(hProcess);
    }

    //std::cout << std::dec << dwProcessId << std::endl;
    return TRUE;
}

int main() {    
    //const char* dllPath = "D:\\C++\\DLLgame\\Debug\\DLLGame.dll";
    const char* dllPath = "D:\\C++\\TestingHooks\\x64\\Debug\\DLLHook.dll";
    DWORD process = GetProcess(targetProcess);
    WIN32InjectDllToProcesS(process, dllPath);
    std::cout << process << std::endl;

    return 0;
}