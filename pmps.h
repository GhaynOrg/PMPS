/*
* File: pmps.h
* Author: DEvil Alghamdi (contact@v0id.me)
* Organization: Ghayn (https://github.com/ghaynorg) (opensource@ghayn.org)
* Description: PMPS stands for Process Memory Pattern Scanner. This file contains the prototypes of this library that help you detect
*              string patterns in a process's memory space (page/region). In this code, we use the page size to iterate through the process memory
*              space to find matches.
* ------------------------------------------------------------------------------------------------------
* License:
* The 3-Clause BSD License
* Copyright 2024 GhaynOrg
* 
* Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
* 
* 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* 
* 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* 
* 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, 
* INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
* OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifndef __PMPS__
#define __PMPS__
#undef UNICODE 
#include <Windows.h>
#include <tlhelp32.h>
#include "re.h"

// Error messages
#define OUT_OF_MEMORY 0x00
#define CAN_NOT_OPEN_PROCESS 0x01
#define CAN_NOT_FIND_PROCESS 0x02

#ifdef __cplusplus
extern "C" {
#endif

    /*
    * All declarations are named in CamelCase
    * to match Windows API naming conventions.
    */
    typedef struct {
        BYTE* memDumpBuffer;
        char* stringBuffer;
        char exeName[MAX_PATH];
        int stringBufferLength;
        int offsetOfString;
        int offsetOfMatchedString;
        int offsetOfRegion;
        LPVOID readedRegionAddress;
        int pageSize;
        LPVOID queryAddress;
        DWORD pid; // Process ID
        HANDLE pHandle; // Process handle
        re_t compiledPattern;
    } pm_t;

    /*
    * Create a new instance of Process Matcher for pattern scanning.
    *
    * @param pattern Regex pattern to scan for.
    *
    * @return Pointer to an Initialized Process Matcher instance.
    */
    pm_t* CreateProcessMatcher(char* pattern);

    /*
    * Find the handle of a process by its process ID.
    *
    * @param pm Initialized instance of Process Matcher type data using `CreateProcessMatcher`.
    * @param pid The Process Identifier Number.
    *
    * @return Pointer to the same `pm` parameter, including the process handle if found, or NULL on failure.
    */
    pm_t* GetProcessHandleByPID(pm_t* pm, DWORD pid);

    /*
    * Find the handle of a process using its name.
    *
    * @param pm Initialized instance of Process Matcher type data using `CreateProcessMatcher`.
    * @param process_name Process name ending with `.exe`.
    *
    * @return Pointer to the same `pm` parameter, including the process handle if found, or NULL on failure.
    */
    pm_t* GetProcessHandleByName(pm_t* pm, char* process_name);

    /*
    * This function yields the first pattern it finds but saves the state in the Process Matcher type data you pass as parameter, meaning you can call it to find other blocks one by one.
    * Note: The return value indicates whether a match was found. To access the full match data, use the fields within the pm_t structure, as they are updated with each found block.
    *
    * @param pm Initialized instance of Process Matcher type data using `CreateProcessMatcher` and having the process handle using either `GetProcessHandleByPID` or `GetProcessHandleByName`.
    *
    * @return Pointer of type char that points to the `stringBuffer` field inside the pm_t structure, or NULL when there are no more matches or a match cannot be found.
    */
    char* PMFindMatchBlock(pm_t* pm);

    int GetMatchErrorFlag();

    /*
    * Clean up the Process Matcher created by `CreateProcessMatcher`.
    *
    * @param pm Pointer to the Process Matcher.
    *
    * @return void
    */
    void CleanupProcessMatcher(pm_t* pm);

    /*
    * Perform a mass search on all running processes to find the provided pattern. This can take up to 10 minutes if `strict` is set to FALSE, especially if a Chromium-based app is running with many child processes.
    *
    * @param pattern Regex pattern to scan for.
    * @param strict Boolean parameter. If TRUE, it will skip some known apps like Chrome, Brave, or File Explorer because they may contain the pattern you are trying to find, but they are not the app you are looking for (e.g., trying to find a path pattern will likely trigger explorer.exe). Set to FALSE if you want to search all apps. Refer to the source for the list of known apps.
    *
    * @return Pointer to a Process Matcher instance containing the data of the process where a match was found, or NULL if nothing was found.
    */
    pm_t* PMSearchAllForMatch(char* pattern, int strict);

#ifdef __cplusplus
}
#endif
#endif