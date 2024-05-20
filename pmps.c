// Define and undefine macros in the source file to avoid affecting users of the library.
#define _CRT_SECURE_NO_WARNINGS
#undef UNICODE 

#include "pmps.h"


static DWORD find_pid_by_process_name(char* pn) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    char* p; // Pointer

    // Lower case the user provided pn(process name)
    
    for (p = pn; *p; p++) *p = tolower(*p);

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Iterate through processes to find the one we're looking for
    do {

        // Lower case process name
        for (p = pe32.szExeFile; *p; p++) *p = tolower(*p);

        // If match break to return the PID
        if (strcmp(pe32.szExeFile, pn) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    // Clean up the snapshot object.
    CloseHandle(hProcessSnap);

    return pid;
}

static DWORD get_system_page_size() {
    SYSTEM_INFO sysInfo;
    
    /*
    * For x64 we use GetNativeSystemInfo as stated in https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo
    * "To retrieve accurate information for an application running on WOW64, call the `GetNativeSystemInfo` function."
    */
#if defined(_WIN64)
    GetNativeSystemInfo(&sysInfo);
#else
    GetSystemInfo(&sysInfo);
#endif
    return sysInfo.dwPageSize;
}

static int is_printable(unsigned char c) {
    return (c >= 32 && c <= 126);
}

static int is_control(unsigned char c) {
    return ((c >= 0 && c <= 31) || c == 127);
}

//TODO: Check if the app is hosted by NT AUTHORITY\\SYSTEM
static const char* knownApps[] = { "", "searchapp.exe", "explorer.exe", "[system Process]", "system", "secure System", "registry", 
                                   "smss.exe", "csrss.exe", "wininit.exe","services.exe", "svchost.exe","brave.exe", "chrome.exe"};

static int is_known_app(char* exeName) {
    for (int i = 0; i < sizeof(knownApps) / sizeof(knownApps[0]); i++) {
        // Lower case
        for (char* p = exeName; *p; p++) *p = tolower(*p);

        if (!strcmp(exeName, knownApps[i])) {
            return 1;
        }
    }
    return 0;
}


static int find_string_in_memory_buffer(char* stringBuffer, BYTE* memoryBuffer, int length, int maxStringSize, int minStringSize, int Offset) {
    int in_string = 0;
    int start = 0;
    int buffer_index = 0; // Index to keep track of the current position in the buffer
    int i = Offset;
    for (; i < length; i++) {
        BYTE b = memoryBuffer[i];
        if (!in_string && is_printable((int)b) && !is_control((int)b)) {
            in_string = 1; // true
            start = i;
        }
        else if (in_string && ((!is_printable((int)b)) || is_control((int)b))) {
            in_string = 0; // false

            if (i - start >= minStringSize) {
                int length = i - start;
                if (length > maxStringSize - buffer_index - 1) {
                    length = maxStringSize - buffer_index - 1; 
                }
                strncpy(&stringBuffer[buffer_index], (char*)&memoryBuffer[start], length);
                buffer_index += length;
                stringBuffer[buffer_index] = '\0'; // Null-terminate the string
                return i;
            }
        }
    }
    return -1;

}

/*
*/
static int pageSize = 0;
static int errorFlag = 0;

char* PMFindMatchBlock(pm_t* pm) {
    /*
    * memInfo:
    * Hold the header data of the memory page
    */
    MEMORY_BASIC_INFORMATION memInfo;


    // Query virtual memory
    while (VirtualQueryEx(pm->pHandle, pm->queryAddress, &memInfo, sizeof(memInfo))) {

        /*
         * We are interested in memory regions that are committed (allocated and in use) and either mapped or private (not shared with other processes).
         * For more information about MEM_COMMIT,MEM_MAPPED and MEM_PRIVATE, refer to:
         * - https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
         * - https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
         */
        if (memInfo.State != MEM_COMMIT || (memInfo.Type != MEM_MAPPED && memInfo.Type != MEM_PRIVATE)) {
            // Move to the next region
            goto nextRegion;
        }

        // Get the region size of the queryed memory
        __int64 regionSize = memInfo.RegionSize;
        do {

            // Read/Dump the memory page into the buffer
            if (!ReadProcessMemory(pm->pHandle, (LPBYTE)memInfo.BaseAddress + pm->offsetOfRegion, pm->memDumpBuffer, pageSize, NULL)) {
                break; // Break if reading fails
            }
            pm->readedRegionAddress = (LPBYTE)memInfo.BaseAddress + pm->offsetOfRegion;

            // Process the readed memory
            while (pm->offsetOfString < pageSize) {
                // Find a string in the dumped memory
                pm->offsetOfString = find_string_in_memory_buffer(pm->stringBuffer, pm->memDumpBuffer, pageSize, pageSize, 5, pm->offsetOfString);
                if (pm->offsetOfString == -1) {
                    // Reset the string buffer and break if no strings are found
                    memset(pm->stringBuffer, 0, pm->stringBufferLength);
                    break;
                }

                // Process the extracted string to find a regex match
                int match_length;
                int m = re_matchp(pm->compiledPattern, pm->stringBuffer, &match_length);
                if (m == -1) {
                    // Reset the string buffer if no match is found
                    memset(pm->stringBuffer, 0, pm->stringBufferLength);
                    continue;
                }

                // Calculate the real offset of the matched string
                pm->offsetOfMatchedString = pm->offsetOfString - (int)strlen(pm->stringBuffer);

                // Move to the next page/region before returning to start the next search from there
                pm->queryAddress = (LPBYTE)memInfo.BaseAddress + memInfo.RegionSize;

                // Return the matched string (address)
                return pm->stringBuffer;
            }

            pm->offsetOfRegion += pageSize;
        } while (pm->offsetOfRegion < regionSize);

        // Reset the offsetOfRegion after iterating over the region
        pm->offsetOfRegion = 0;
    nextRegion:
        pm->queryAddress = (LPBYTE)memInfo.BaseAddress + memInfo.RegionSize;
    }
    // No match at all or No more memory to query
    return NULL;
}

pm_t* PMSearchAllForMatch(char* pattern, int strict) {
    //TODO: Duplicated code from find_pid_by_process_name clean it later

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)) {
        CloseHandle(hProcessSnap);
        return 0;
    }

    char* matchedBuffer;
    pm_t* pm;
    
    do {
        if (strict) {
            //! Don't do (strict && is_known_app(pe32.szExeFile)) because then will happen unnecessary call for the is_known_app function
            // Skip known apps
            if (is_known_app(pe32.szExeFile)) continue;
        }
        // Create new instance for search
        pm = CreateProcessMatcher(pattern);

        if ((pm = GetProcessHandleByName(pm,pe32.szExeFile)) == NULL) {
            goto cleanup;
        }

        // Iterate until a match found
        while ((matchedBuffer = PMFindMatchBlock(pm)) != NULL) {
            memcpy(pm->exeName , pe32.szExeFile,strlen(pe32.szExeFile));
            pm->pid = pe32.th32ProcessID;
            return pm;
        }
    cleanup:;
        // Clean for another search
        CleanupProcessMatcher(pm);
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return NULL;
}

pm_t* GetProcessHandleByPID(pm_t* pm, DWORD pid) {

    /*
    * Obtain a handle with the necessary access rights to read the process memory and query information.
    * -------------------------------------------------------------------------------------------------
    * Note:
    *   For more information about PROCESS_VM_READ and PROCESS_QUERY_INFORMATION, refer to
    *   https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights.
    *   For details about the OpenProcess function, refer to
    *   https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess.
    *
    * Brief:
    *   Open the process using the OpenProcess function and request PROCESS_VM_READ (for ReadProcessMemory) and PROCESS_QUERY_INFORMATION
    *   (for VirtualQueryEx), which grant the necessary access to read the process memory and query information about the process.
    */
    HANDLE pHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (pHandle == NULL) {
        errorFlag = CAN_NOT_FIND_PROCESS;
        return NULL;
    }

    pm->pHandle = pHandle;
    pm->pid = pid;
    return pm;
}

pm_t* GetProcessHandleByName(pm_t* pm, char* process_name) {
    // TODO: Once the function find the process it open it and sets the handle.
    DWORD pid = find_pid_by_process_name(process_name);
    if (pid == 0) {
        errorFlag = CAN_NOT_FIND_PROCESS;
        return NULL;
    }
    pm->pid = pid;
    memcpy(pm->exeName, process_name,strlen(process_name));
    return GetProcessHandleByPID(pm, pid);
}

int GetMatchErrorFlag() {
    return errorFlag;
}

pm_t* CreateProcessMatcher(char* pattern) {
    // Allocate memory for the struct on the heap
    pm_t* pm = malloc(sizeof(pm_t));
    if (pm == NULL) {
        return NULL;
    }

    /*
    * Initialize the struct by setting all its fields to zero.
    * Explanation:
    * When you allocate memory in C, the memory may contain previous data from its use or random values.
    * If a field, such as "offsetOfRegion", is used without being assigned a value, it may contain a large or invalid value,
    * which can lead to unexpected behavior or crashes (e.g., access violation). To prevent this, we use memset to
    * set all fields of the struct to zero, ensuring that they start with a known state.
    * Note:
    * Although calloc could also be used to allocate and zero-initialize the memory, I prefer this approach for its simplicity.
    */
    memset(pm, 0, sizeof(*pm));

    /*
    * The page size is typically 4KB, but to ensure accuracy, we retrieve it from the SYSTEM_INFO.
    * https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
    */
    pageSize = get_system_page_size();
    pm->pageSize = pageSize;

    /*
    * Allocate memory for the buffer that will store the dumped memory page.
    * This buffer will hold the contents of the memory page being scanned.
    */
    pm->memDumpBuffer = (BYTE*)malloc(pageSize);
    if (pm->memDumpBuffer == NULL) {
        free(pm);
        return;
    }

    /*
    * Allocate memory for the buffer that will hold the matched string block.
    *
    * What is a String Block?
    * The matched string is not extracted directly. Instead, this library returns the entire string block in which a match is found.
    * This approach gives the user full control over the block of string data, which may contain additional information that the user finds interesting.
    */
    pm->stringBuffer = malloc(pageSize);
    if (pm->stringBuffer == NULL) {
        free(pm->stringBuffer);
        free(pm);
        return NULL;
    }

    pm->stringBufferLength = pageSize;
    pm->compiledPattern = re_compile(pattern);
    return pm;
}

void CleanupProcessMatcher(pm_t* pm) {
    if (pm == NULL) return;

    if (pm->stringBuffer != NULL) {
        free(pm->stringBuffer);
    }
    if (pm->memDumpBuffer != NULL) {
        free(pm->memDumpBuffer);
    }
    memset(pm, 0, sizeof(*pm));
    free(pm);
}