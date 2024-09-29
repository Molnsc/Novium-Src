#include <windows.h>
#include <iostream>

void InjectVIPER(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open process." << std::endl;
        return;
    }

    
    void* pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pDllPath, (void*)dllPath, strlen(dllPath) + 1, NULL);

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pDllPath, 0, NULL);

   
    CloseHandle(hProcess);
}

int main() {
    DWORD processID; 
    const char* dllPath = "C:\\sep\\vi\\novium\\sebl.dll";
    InjectDLL(processID, dllPath);
    return 0;
}
