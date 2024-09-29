#include <iostream>
#include <windows.h>
#include <tlhelp32.h>

bool InjectDLL(const char* processName, const char* dllPath) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[Novium] Failed to take process snapshot." << std::endl;
        return false;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &processEntry)) {
        std::cerr << "[Novium] Failed to get first process." << std::endl;
        CloseHandle(snapshot);
        return false;
    }

    DWORD processId = 0;
    do {
        if (!_stricmp(processEntry.szExeFile, processName)) {
            processId = processEntry.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &processEntry));

    CloseHandle(snapshot);

    if (processId == 0) {
        std::cerr << "[Novium] Could not find the process." << std::endl;
        return false;
    }

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (processHandle == NULL) {
        std::cerr << "[Novium] Failed to open target process." << std::endl;
        return false;
    }

    LPVOID allocatedMemory = VirtualAllocEx(processHandle, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocatedMemory == NULL) {
        std::cerr << "[Novium] Failed to allocate memory in target process." << std::endl;
        CloseHandle(processHandle);
        return false;
    }

    if (!WriteProcessMemory(processHandle, allocatedMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cerr << "[Novium] Failed to write DLL path to target process memory." << std::endl;
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    HMODULE kernel32 = GetModuleHandle("Kernel32");
    if (kernel32 == NULL) {
        std::cerr << "[Novium] Failed to get handle of Kernel32." << std::endl;
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(kernel32, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        std::cerr << "[Novium] Failed to get address of LoadLibraryA." << std::endl;
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMemory, 0, NULL);
    if (remoteThread == NULL) {
        std::cerr << "[Novium] Failed to create remote thread in target process." << std::endl;
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    WaitForSingleObject(remoteThread, INFINITE);
    VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
    CloseHandle(remoteThread);
    CloseHandle(processHandle);

    std::cout << "DLL injected successfully!" << std::endl;
    return true;
}

int main() {
    const char* processName = "RobloxPlayerBeta.exe";
    const char* dllPath = "C:\\sep\\vi\\novium\\trag.dll";

    if (!InjectDLL(processName, dllPath)) {
        std::cerr << "[Novium] DLL injection failed." << std::endl;
    }

    return 0;
}
