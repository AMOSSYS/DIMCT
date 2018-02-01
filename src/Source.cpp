#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#pragma pack(push)
#pragma pack(1)
typedef struct _hijack {
    ULONG dwSize;
    ULONG relativeAddress;
    ULONG relocsCount;
    ULONG savedBytesSize;
    ULONG allignNops;
    BYTE savedBytes[1];                // defined by "savedBytesSize"
    ULONG relocs[1];
} hijack, *phijack;

typedef struct _zoneEntry {
    PVOID callee;
    PVOID caller;
}zoneEntry;
typedef struct _zoneStruct {
    BYTE localLock;
    BYTE reserved;        // not used
    ULONG dataSize;            
    zoneEntry entries[1];
}zoneStruct, *pzoneStruct;
#pragma pack(pop)

#define WAITTIME 100
#define SHAREDMEM_SIZE 0x80000
#define ZEROMEM_SIZE 0x10

PVOID gPseudoSharedMemory = NULL;
BYTE gZeroMem[ZEROMEM_SIZE] = { 0 };
char* gModuleName = NULL;
ULONG gHijackCounts = 0;
phijack gHijacks = NULL;




/*
    Dumps the remote memory region in the log.bin file. Reset the memory region globals.
*/
BOOL __fastcall dumpMem(HANDLE hProcess) {
    FILE* fHandle;
    BYTE xZone[SHAREDMEM_SIZE];
    ULONG dwSz, zoneSize;
    BYTE lockZone[] = { 0x1, 0x1 };

    if (ReadProcessMemory(hProcess, (PVOID)((ULONG)gPseudoSharedMemory), xZone, sizeof(zoneStruct), &dwSz) == FALSE)
        return FALSE;

    zoneSize = ((pzoneStruct)xZone)->dataSize;
    if (zoneSize != 0) {

        // write mutex(es)
        if (WriteProcessMemory(hProcess, gPseudoSharedMemory, &lockZone, sizeof(lockZone), &dwSz) == FALSE) {
            printf("[i] Error: WriteProcessMemory error, aborting monitoring.\n");
            return FALSE;
        }

        // wait to let other threads log if they need to (... yes, I know.)
        Sleep(50);

#ifdef _DEBUG
        printf("[d] Zone dump 0x%x!\n", zoneSize);
#endif
        // read and dump
        if (ReadProcessMemory(hProcess, (PVOID)((ULONG)gPseudoSharedMemory + 6), xZone, zoneSize, &dwSz) == TRUE) {

            if (fopen_s(&fHandle, "log.bin", "ab") != 0) {
                printf("[i] Error: Could not open log.bin file for writing, aborting monitoring.\n");
                return FALSE;
            }

            fwrite(xZone, 1, dwSz, fHandle);
            fclose(fHandle);
            fHandle = NULL;
        }
        else {
            printf("[i] Error: ReadProcessMemory error, aborting monitoring.\n");
            return FALSE;
        }

        // zero the size
        if (WriteProcessMemory(hProcess, (PVOID)((SIZE_T)gPseudoSharedMemory + FIELD_OFFSET(zoneStruct, dataSize)), &gZeroMem, sizeof(ULONG), &dwSz) == FALSE) {
            printf("[i] Error: WriteProcessMemory error, aborting monitoring.\n");
            return FALSE;
        }

        // release the mutex
        if (WriteProcessMemory(hProcess, (PVOID)((SIZE_T)gPseudoSharedMemory), &gZeroMem, sizeof(BYTE) * 2, &dwSz) == FALSE) {
            printf("[i] Error: WriteProcessMemory error, aborting monitoring.\n");
            return FALSE;
        }
    }

    return TRUE;
}

/*
    Adjusts the process priority to be above the target, and monitor the memory region every 100ms.
*/
BOOL __fastcall monitorZone(ULONG waitTime, HANDLE hProcess) {
    ULONG code = 0;
    ULONG waitSt = GetTickCount();
    waitTime = waitTime * 1000;
    ULONG targetPriority = 0;

    targetPriority = GetPriorityClass(hProcess);
#ifdef _DEBUG
    printf("[d] Target's priority class is 0x%x\n", targetPriority);
#endif
    if (targetPriority >= NORMAL_PRIORITY_CLASS) {
        if (targetPriority == NORMAL_PRIORITY_CLASS)
            SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);
        else if (targetPriority == ABOVE_NORMAL_PRIORITY_CLASS)
            SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
        else if (targetPriority == HIGH_PRIORITY_CLASS)
            SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

#ifdef _DEBUG
        printf("[d] Current priority class has been set to 0x%x\n", GetPriorityClass(GetCurrentProcess()));
#endif
    }

    printf("[i] Monitoring started!\n");

    while (GetTickCount() - waitSt < waitTime) {
        if (dumpMem(hProcess) == FALSE)
            goto end;

        if (GetExitCodeProcess(hProcess, &code) != 0) {
            if (code != STILL_ACTIVE) {
                code = 1;
                break;
            }
        }
        code = 0;
        Sleep(100);
    }

    if(code == 0)
        dumpMem(hProcess);

end:

    return TRUE;
}

/*
    Loads the configuration file.
*/
BOOL __fastcall readConfig() {
    LPVOID data = NULL;
    LARGE_INTEGER fileSize = { 0 };
    HANDLE hFile = NULL;
    DWORD read = 0;
    char* ptr = NULL;

    printf("[i] Reading configuration\n");

    hFile = CreateFileA("config.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[i] Error: failed to CreateFile\n");
        return FALSE;
    }

    if (GetFileSizeEx(hFile, &fileSize) == 0) {
        printf("[i] Error: failed to GetFileSizeEx\n");
        return FALSE;
    }

    data = malloc(fileSize.LowPart); 
    if (data == NULL) {
        printf("[i] Error: failed to malloc\n");
        return FALSE;
    }

    if (!ReadFile(hFile, data, fileSize.LowPart, &read, NULL)) {
        printf("[i] Error: failed to ReadFile\n");
        return FALSE;
    }

    gModuleName = (char*)data;
    printf("[i] Module name: %s\n", gModuleName);

    ptr = (char*)data;
    while (*ptr != 0x0)
        ptr++;

    ptr++;
    gHijackCounts = *(PULONG)ptr;
    printf("[i] Hijacks: %d\n", gHijackCounts);

    ptr += sizeof(ULONG);
    gHijacks = (phijack)ptr;

    return TRUE;
}

/*
    Helper to calculate a JMP opcode.
*/
ULONG __inline MakeJmp(DWORD pAddress, DWORD dwJumpTo) {
    return  dwJumpTo - pAddress  - 5;
}

/**
    1. Locate the target module
    2. Suspend threads
    3. Allocate memory areas
    5. Install hooks
        a. copy overwitten/updated bytes
        b. update trampoline
        c. install hook
    6. Resume threads

    Memory areas:

        Logged data 
                    [ mutex              ]
                    [ log entry          ]
                    [     ...            ]
                    [ log entry          ]

        Function
                    [ push eax              ]                <---- hook
                    [ mov eax, trampoline ]
                    [ call logger          ]
                    [ nop * N              ]
                    [ ...                  ]                <---- return addr

        Logger      
                    [ pop eax            ]                <---- gets trampoline addr
                    [ pop saved eip(s)   ]
                    [ check bounds       ]
                    [ acquire mutex      ]
                    [ log                ]                <---- logs if intermodule call
                    [ release mutex      ]
                    [ JMP eax            ]                <---- jmps to the trampoline
        Trampolines
                    [ original function instructions ]        <---- original function opcodes (updated)
                    [ JMP original function +X       ]        <---- JMP back to the original function
                    [ original function instructions ]
                    [ JMP original function +X       ]
                    [ original function instructions ]
                    [ JMP original function +X       ]
                    [ ...                            ]

*/
BOOL __fastcall injectByHandle(HANDLE hProcess) {

    SIZE_T szWritten = 0;
    HANDLE hThread[0x200] = { NULL }, hSnap = NULL;;
    ULONG hThreadCount = 0, c = 0, trampolinesSize = 0, z = 0;
    BOOL stat = FALSE;
    WCHAR modNameW[MAX_PATH];
    THREADENTRY32 threadData = { 0 };
    MODULEENTRY32W modData = { 0 };
    phijack hiPtr = NULL;
    PVOID trampolinesArea = NULL, trampolinesAreaPtr = NULL, funcAddr = NULL, shellcodeAddr = NULL, modStart = NULL, modEnd = NULL, trampTrampArea = NULL, trampTrampAreaPtr = NULL;
    FILE* fHandle = NULL;
    PULONG relocsPtr = NULL;


    
#define shellcodeModuleBaseAddr        0xE
#define shellcodeModuleBaseEndAddr    0x16
#define shellcodeSharedMemAddr        0x1F
#define shellcodeSharedMemSizeAddr    0x39
    //#define _DBGSHC 0

#ifdef _DBGSHC
#define shellcodeModuleBaseAddr 0xF
#define shellcodeModuleBaseEndAddr 0x17
#define shellcodeSharedMemAddr 0x20
#define shellcodeSharedMemSizeAddr 0x3A
#endif

    BYTE mainShellcode[] = {
#ifdef _DBGSHC
     0xCC,                                        // int 3
#endif
     0x60,                                        // pusha
     0x9c,                                        // pushf
     0x3E, 0x8B, 0x5C, 0x24, 0x28,                // mov ebx, [esp + 28]                    ; callee
     0x3E, 0x8B, 0x4C, 0x24, 0x2C,                // mov ecx, [esp + 2C]                    ; caller
     0x81, 0xF9, 0xEF, 0xBE, 0xAD, 0xDE,        // cmp ecx, 0xDEADBEEF                    ; check module range
     0x76, 0x0A,                                // jbe okaylog
     0x81, 0xF9, 0xEF, 0xBE, 0xAD, 0xDE,        // cmp ecx, 0xDEADBEEF
     0x77, 0x02,                                // ja okaylog
     0xEB, 0x33,                                // jmp dontlog
// okaylog:
     0xBE, 0xEF, 0xBE, 0xAD, 0xDE,                // mov esi, 0xDEADBEEF                    ; "shared" memory address
// waitmutex:
     0x53,                                        // push   ebx
     0x50,                                        // push   eax
// waitmutex2:
     0xB0, 0x00,                                // mov    al,0x0
     0xB3, 0x01,                                // mov    bl,0x1
     0xF0, 0x0F, 0xB0, 0x1E,                    // lock cmpxchg BYTE PTR [esi],bl        ; acquiring the local mutex
     0x75, 0xF6,                                // jne    waitmutex2
     0x58,                                        // pop eax
     0x5B,                                        // pop ebx
     0x8B, 0x7E, 0x02,                            // mov edi, dword ptr ds:[esi+2]        ; reads the size
     0x83, 0xC7, 0x08,                            // add edi, 8
     0x81, 0xFF, 0xEF, 0xBE, 0xAD, 0xDE,        // cmp edi, 0xDEADBEEF                    ; compares with SHAREDMEM_SIZE in order to check if enough space is left
     0x72, 0x02,                                // jb log
     0xEB, 0xE2,                                // jmp waitmutex
// log:
     0x89, 0x7E, 0x02,                            // mov dword ptr ds:[esi + 2], edi        ; updates size
     0x01, 0xF7,                                // add edi, esi                            ; gets the data pointer
     0x83, 0xEF, 0x02,                            // sub edi, 2
     0x89, 0x1F,                                // mov dword ptr ds:[edi], ebx            ; logs the caller
     0x89, 0x4F, 0x04,                            // mov dword ptr ds:[edi + 4], ecx        ; logs the callee
     0xC6, 0x06, 0x00,                            // mov byte ptr ds:[esi], 0                ; mutex release
// dontlog:
     0x9D,                                        // popf
     0x61,                                        // popa
     0xFF, 0xE0                                    // jmp eax                                ; jumps to the trampoline
    };

#define simpleShcTrampolineAddr 0x2
#define simpleShcCallAddr 0x7
#define simpleShellcodeSize 0xB

    BYTE simpleShellcode[] = { 
// layer_1_trampoline:
        0x50,                                    // push eax                                ; saves the register
        0xB8, 0xEF, 0xBE, 0xAD, 0xDE,            // mov eax, 0xdeadbeef                    ; trampoline address
        0xE9, 0xEF, 0xBE, 0xAD, 0xDE,            // jmp 0xdeadbeef                        ; calls the log function
    };

    // just a JMP
    BYTE simpleJmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };

    // CALL + nopsled (hook)
#define jmpShellcodeSize 0x5
    BYTE jmpShellcode[] = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };




// 1. Locate the target module

    if (MultiByteToWideChar(CP_UTF8, 0, gModuleName, strlen(gModuleName) + 1, modNameW, MAX_PATH) == 0) {
        printf("[i] Error: error on MultiByteToWideChar\n");
        goto end;
    }

#ifdef _DEBUG
    printf("[d] Searching %S module\n", modNameW);
#endif

    if (fopen_s(&fHandle, "log.bin", "wb") != 0) {
        printf("[i] Error: could not open log.bin for writing.\n");
        goto end;
    }

    // let's find the module in memory and log the loaded modules
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("[i] Error: error on CreateToolhelp32Snapshot\n");
        goto end;
    }

    memset(&modData, 0, sizeof(modData));
    modData.dwSize = sizeof(modData);

    stat = Module32FirstW(hSnap, &modData);
    while (stat == TRUE) {

        fprintf(fHandle, "%S!%.8x!%.8x|", modData.szModule, modData.modBaseAddr, modData.modBaseAddr + modData.modBaseSize);

        if (!_wcsnicmp(modData.szModule, modNameW, MAX_PATH)) {
            modStart = modData.modBaseAddr;
            modEnd = modData.modBaseAddr + modData.modBaseSize;
        }

        stat = Module32Next(hSnap, &modData);
    }

    CloseHandle(hSnap);

    fprintf(fHandle, "|");
    fclose(fHandle);

    if (modStart == NULL) {
        printf("[i] Error: module not found.\n");
        goto end;
    }


// 2. Suspend threads


#ifdef _DEBUG
    printf("[d] Suspending threads\n");
#endif
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetProcessId(hProcess));
    
    memset(&threadData, 0, sizeof(threadData));
    threadData.dwSize = sizeof(threadData);
    stat = Thread32First(hSnap, &threadData);
    while (stat == TRUE) {
        if (threadData.th32OwnerProcessID == GetProcessId(hProcess)) {
            hThread[hThreadCount] = OpenThread(THREAD_ALL_ACCESS, FALSE, threadData.th32ThreadID);
            SuspendThread(hThread[hThreadCount]);
            hThreadCount++;
#ifdef _DEBUG
            printf("\t[d] %d suspended\n", threadData.th32ThreadID);
#endif
        }
        stat = Thread32Next(hSnap, &threadData);
    }
    CloseHandle(hSnap);


// 3. Allocate memory


#ifdef _DEBUG
    printf("[d] Allocating \"shared\" mem\n");
#endif

    gPseudoSharedMemory = VirtualAllocEx(hProcess, NULL, SHAREDMEM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (gPseudoSharedMemory == NULL) {
        printf("[i] Error: memory allocation failed (1).\n");
        goto end;
    }
    if (WriteProcessMemory(hProcess, gPseudoSharedMemory, gZeroMem, ZEROMEM_SIZE, &szWritten) == FALSE){
        printf("[i] Error: memory allocation failed (2).\n");
        goto end;
    }
    
#ifdef _DEBUG
    printf("[d] Patching main shellcode\n");
#endif

    * (PULONG)(mainShellcode + shellcodeModuleBaseAddr) = (ULONG)modStart;
    *(PULONG)(mainShellcode + shellcodeModuleBaseEndAddr) = (ULONG)modEnd;
    *(PULONG)(mainShellcode + shellcodeSharedMemAddr) = (ULONG)gPseudoSharedMemory;
    *(PULONG)(mainShellcode + shellcodeSharedMemSizeAddr) = SHAREDMEM_SIZE;

#ifdef _DEBUG
    printf("[d] Writing shellcode\n");
#endif

    // copie du main shellcode
    shellcodeAddr = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (shellcodeAddr == NULL) {
        printf("[i] Error: memory allocation failed (3).\n");
        goto end;
    }
    if (WriteProcessMemory(hProcess, shellcodeAddr, mainShellcode, sizeof(mainShellcode), &szWritten) == FALSE) {
        printf("[i] Error: memory allocation failed (4).\n");
        goto end;
    }


#ifdef _DEBUG
    printf("[d] Allocating trampolines area\n");
#endif

    // we need to compute the needed size before allocation
    hiPtr = gHijacks;
    trampolinesSize = 0;
    for (c = 0; c < gHijackCounts; c++) {
        trampolinesSize += hiPtr->savedBytesSize + 5;
        hiPtr = (phijack)((SIZE_T)hiPtr + hiPtr->dwSize);
    }
    trampolinesArea = VirtualAllocEx(hProcess, NULL, trampolinesSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (trampolinesArea == NULL) {
        printf("[i] Error: memory allocation failed (5).\n");
        goto end;
    }

    // tramp tramp trampoliiine
    trampTrampArea = VirtualAllocEx(hProcess, NULL, gHijackCounts*sizeof(simpleShellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (trampTrampArea == NULL) {
        printf("[i] Error: memory allocation failed (6).\n");
        goto end;
    }



// 4. Place hooks

#ifdef _DEBUG
    printf("[d] Hooking functions\n");
#endif
    
    trampolinesAreaPtr = trampolinesArea;
    trampTrampAreaPtr = trampTrampArea;
    hiPtr = gHijacks;
    for (c = 0; c < gHijackCounts; c++) {

#ifdef _DEBUG
        printf("\t%.8x\n", hiPtr->relativeAddress + (SIZE_T)modStart);
#endif

// UPDATE SHELLCODES

        // relative address (in memory)
        funcAddr = (PVOID)((SIZE_T)modStart + hiPtr->relativeAddress);

        // updating relocs in saved bytes
        if (hiPtr->relocsCount != 0) {
            relocsPtr = (PULONG)(hiPtr->savedBytes + hiPtr->savedBytesSize);
            for (z = 0; z<hiPtr->relocsCount; z++)
                *(PULONG)(hiPtr->savedBytes + relocsPtr[z]) = *(PULONG)(hiPtr->savedBytes + relocsPtr[z]) + (ULONG)modStart;
        }

        // updating the SAVEDBYTES -> JMP <backtofunction>
        *(PULONG)(simpleJmp + 1) = MakeJmp((ULONG)trampolinesAreaPtr + hiPtr->savedBytesSize, (ULONG)funcAddr + jmpShellcodeSize + hiPtr->allignNops);

        // updating the tramp trampoline -> PUSH/JMP
        *(PULONG)(simpleShellcode + simpleShcTrampolineAddr) = (ULONG)trampolinesAreaPtr;                                            // PUSH <final trampoline>
        *(PULONG)(simpleShellcode + simpleShcCallAddr) = MakeJmp((ULONG)trampTrampAreaPtr + simpleShcCallAddr - 1, (ULONG)shellcodeAddr);    // JMP <logger>

        // updating the hook
        *(PULONG)(jmpShellcode + 1) = MakeJmp((ULONG)funcAddr, (ULONG)trampTrampAreaPtr);

// COMMIT

        // copy the tramptrampoline
        if (WriteProcessMemory(hProcess, trampTrampAreaPtr, simpleShellcode, sizeof(simpleShellcode), &szWritten) == FALSE) {
            printf("[i] Error: trampoline write failed (0)\n");
            continue;
        }

        // copy the original bytes + return to original function
        if (WriteProcessMemory(hProcess, trampolinesAreaPtr, hiPtr->savedBytes, hiPtr->savedBytesSize, &szWritten) == FALSE) {
            printf("[i] Error: trampoline write failed (1)\n");
            continue;
        }

        // copy the return JMP
        if (WriteProcessMemory(hProcess, (PVOID)((ULONG)trampolinesAreaPtr + hiPtr->savedBytesSize), simpleJmp, 5, &szWritten) == FALSE) {
            printf("[i] Error: trampoline write failed (2)\n");
            continue;
        }

        // update, unprotect and copy the hook
        VirtualProtectEx(hProcess, funcAddr, jmpShellcodeSize + hiPtr->allignNops, PAGE_EXECUTE_READWRITE, &szWritten);
        if (WriteProcessMemory(hProcess, funcAddr, jmpShellcode, jmpShellcodeSize + hiPtr->allignNops, &szWritten) == FALSE) {
            printf("[i] Error: trampoline write failed (3)\n");
            continue;
        }

        // update the pointers if everything suceeded
        trampolinesAreaPtr = (PVOID)((SIZE_T)trampolinesAreaPtr + hiPtr->savedBytesSize + 5);
        trampTrampAreaPtr = (PVOID)((SIZE_T)trampTrampAreaPtr + sizeof(simpleShellcode));
        hiPtr = (phijack)((SIZE_T)hiPtr + hiPtr->dwSize);
    }


// 5. Resume threads

    printf("[i] Injected successfully!\n");
    stat = TRUE;

end:

#ifdef _DEBUG
    printf("[d] Resuming threads\n");
#endif

    for (c = 0; c < hThreadCount; c++)
        ResumeThread(hThread[c]);

    return stat;
}


/*
    Opens the process, injects hooks and monitor it. Then kill it.
*/
BOOL __fastcall payload(ULONG pid, ULONG wait) {
    BOOL status = FALSE;
    HANDLE hProcess = NULL;

    hProcess = NULL;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
        printf("[d] OpenProcess error!\n");
#endif
        return FALSE;
    }

    status = injectByHandle(hProcess);
    if (status == TRUE)
        status = monitorZone(wait, hProcess);

    if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
        TerminateProcess(hProcess, -1);
        CloseHandle(hProcess);
        hProcess = NULL;
    }
    
    return status;
}

/*
    Main
*/
int __cdecl main(int argc, char**argv) {
    ULONG wait = 0;
    ULONG pid = 0;

    if (argc <= 2){
        printf("Usage: %s <pid> <wtime>\n", argv[0]);
        printf("\tpid: Process ID\n");
        printf("\twtime: wait time (seconds) before killing the process\n");
        printf("\tconfig.bin must be present (IDA Python output)\n");
        return 0;
    }
        
    pid = atol(argv[1]);
    wait = atol(argv[2]);

    if (readConfig() == FALSE) {
        printf("[i] Error: bad config data!\n");
        return 0;
    }

    printf("[i] Press a key to start. Monitored process will be killed after %d seconds.\n", wait);
    system("pause");

    if (payload(pid, wait) == FALSE)
        printf("[i] Monitoring failed!\n"); 
    else
        printf("[i] Monitoring ended!\n");

    return 0;

}
