#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <sstream>

using json = nlohmann::json;

struct Node {
    std::string processName;
    std::string dllPath;
    DWORD processId;
    bool injected;

    json Serialize() {
        return json{{"processName", processName}, {"dllPath", dllPath}, {"processId", processId}, {"injected", injected}};
    }
};

std::vector<Node> nodes;
std::mutex nodesMutex;
std::ofstream logFile("injector.log");

std::string Encrypt(const std::string& data) {
    unsigned char key[16];
    unsigned char iv[16];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    std::string encryptedData;
    int outLen;
    std::vector<unsigned char> buffer(data.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    
    EVP_EncryptUpdate(ctx, buffer.data(), &outLen, reinterpret_cast<const unsigned char*>(data.data()), data.size());
    encryptedData.append(reinterpret_cast<char*>(buffer.data()), outLen);
    
    EVP_EncryptFinal_ex(ctx, buffer.data() + outLen, &outLen);
    encryptedData.append(reinterpret_cast<char*>(buffer.data()), outLen);
    
    EVP_CIPHER_CTX_free(ctx);
    
    return encryptedData;
}

std::string Decrypt(const std::string& encryptedData, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    std::string decryptedData;
    int outLen;
    std::vector<unsigned char> buffer(encryptedData.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    
    EVP_DecryptUpdate(ctx, buffer.data(), &outLen, reinterpret_cast<const unsigned char*>(encryptedData.data()), encryptedData.size());
    decryptedData.append(reinterpret_cast<char*>(buffer.data()), outLen);
    
    EVP_DecryptFinal_ex(ctx, buffer.data() + outLen, &outLen);
    decryptedData.append(reinterpret_cast<char*>(buffer.data()), outLen);
    
    EVP_CIPHER_CTX_free(ctx);
    
    return decryptedData;
}

void Log(const std::string& message) {
    std::lock_guard<std::mutex> lock(nodesMutex);
    logFile << "[Novium] " << message << std::endl;
}

bool IsProcessRunning(const std::string& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    while (Process32Next(snapshot, &processEntry)) {
        if (_stricmp(processEntry.szExeFile, processName.c_str()) == 0) {
            CloseHandle(snapshot);
            return true;
        }
    }

    CloseHandle(snapshot);
    return false;
}

bool InjectDLL(Node& node) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        Log("Failed to take process snapshot.");
        return false;
    }

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    while (Process32First(snapshot, &processEntry)) {
        if (_stricmp(processEntry.szExeFile, node.processName.c_str()) == 0) {
            node.processId = processEntry.th32ProcessID;
            break;
        }
        Process32Next(snapshot, &processEntry);
    }

    CloseHandle(snapshot);

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, node.processId);
    if (processHandle == NULL) {
        Log("Failed to open target process.");
        return false;
    }

    LPVOID allocatedMemory = VirtualAllocEx(processHandle, NULL, node.dllPath.size() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (allocatedMemory == NULL) {
        Log("Failed to allocate memory in target process.");
        CloseHandle(processHandle);
        return false;
    }

    if (!WriteProcessMemory(processHandle, allocatedMemory, node.dllPath.c_str(), node.dllPath.size() + 1, NULL)) {
        Log("Failed to write DLL path to target process memory.");
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    HMODULE kernel32 = GetModuleHandle("Kernel32");
    if (kernel32 == NULL) {
        Log("Failed to get handle of Kernel32.");
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(kernel32, "LoadLibraryA");
    if (loadLibraryAddr == NULL) {
        Log("Failed to get address of LoadLibraryA.");
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMemory, 0, NULL);
    if (remoteThread == NULL) {
        Log("Failed to create remote thread in target process.");
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }

    WaitForSingleObject(remoteThread, INFINITE);
    VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
    CloseHandle(remoteThread);
    CloseHandle(processHandle);

    node.injected = true;
    Log("DLL injected successfully into " + node.processName);
    return true;
}

void MonitorProcesses() {
    while (true) {
        for (auto& node : nodes) {
            if (!node.injected) {
                if (IsProcessRunning(node.processName)) {
                    InjectDLL(node);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}

void LoadConfiguration(const std::string& configFile) {
    std::ifstream file(configFile);
    if (!file.is_open()) {
        Log("Failed to open configuration file.");
        return;
    }

    json config;
    file >> config;

    for (const auto& item : config) {
        Node node;
        node.processName = item["RobloxPlayerBeta"];
        node.dllPath = item["C:\\nova\\v2\\jumbo.dll"];
        node.processId = 0;
        node.injected = false;
        nodes.push_back(node);
    }
}

void SaveNodes() {
    std::lock_guard<std::mutex> lock(nodesMutex);
    json nodeData;
    for (const auto& node : nodes) {
        nodeData.push_back(node.Serialize());
    }

    std::ofstream file("nodes.json");
    file << nodeData.dump(4);
}

void CheckInjectionStatus() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        for (const auto& node : nodes) {
            if (node.injected && !IsProcessRunning(node.processName)) {
                Log("Process " + node.processName + " is no longer running, resetting injected state.");
                const_cast<Node&>(node).injected = false;
            }
        }
        SaveNodes();
    }
}

void DisplayHelp() {
    
}

int main(int argc, char* argv[]) {
    if (argc > 1) {
        std::string command = argv[1];
        if (command == "--help") {
            DisplayHelp();
            return 0;
        }
    }

    LoadConfiguration("config.json");

    std::thread monitorThread(MonitorProcesses);
    monitorThread.detach();

    std::thread statusThread(CheckInjectionStatus);
    statusThread.detach();

    std::cout << "Novium Injector running. Press Enter to exit." << std::endl;
    std::cin.get();

    logFile.close();
    return 0;
}
