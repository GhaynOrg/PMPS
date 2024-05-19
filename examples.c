#define _CRT_SECURE_NO_WARNINGS

#undef UNICODE // Only use Ascii

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Process Memory Pattern Scanner
#include "pmps.h"

int example1() {
    char regex[4096]; //! Danger change this
    char process_name[4096]; //! Danger change this
    printf("=====================================\n");
    printf("This tool is intended to search for null-terminated texts buffers into a process's memory using regex\n");
start:
    printf("[?] Process: ");
    scanf("%s", process_name); //! Danger change this
    printf("[?] Regex: ");
    scanf("%s", regex); //! Danger change this

    pm_t* pm = CreateProcessMatcher(regex);
    pm = GetProcessHandleByName(pm, process_name);
    if ((pm) == NULL) {
        CleanupProcessMatcher(pm);
        printf("[-] Error while GetProcessHandle\n");
        return 1;
    }
    printf("\n");
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);

    printf("Start searching...\n\n");

    // Find match
    char* matchedBuffer;
    while ((matchedBuffer = PMFindMatchBlock(pm)) != NULL) {
        // isprint(b) ? b : "."
        int hitMatchOffset = 0;
        printf("===============================================");
        printf("\n\n");
        printf("Found match\nAddress [0x%p] Page/Region [0x%p]\n", pm->queryAddress, pm->readedRegionAddress);
        for (int i = 0; i < pm->pageSize; i++) {
            BYTE b = pm->memDumpBuffer[i];

            if (b == 0x00 && hitMatchOffset) {
                hitMatchOffset = 0;
                printf("\x1b[0m");
            }
            if (i == pm->offsetOfMatchedString && !hitMatchOffset) {
                printf("\x1b[0;33m");
                hitMatchOffset = 1;
            }

            printf("%02X ", b);

            if ((i + 1) % 16 == 0 || i == pm->pageSize - 1) {
                // Print ASCII representation
                printf(" ");
                for (int j = i - (i % 16); j <= i; j++) {
                    BYTE ascii = pm->memDumpBuffer[j];
                    if (ascii >= 32 && ascii <= 126) {
                        printf("%c", ascii);
                    }
                    else {
                        printf(".");
                    }
                }
                printf("\n");
            }
        }

    }



    //Clean up before you leave
    CleanupProcessMatcher(pm);

    return 0;
}

int example2() {
    const char* ida_patters = "[Ii][Dd][Aa] [Ff]reeware\s*";
    pm_t* pm = PMSearchAllForMatch(ida_patters, TRUE);
    printf("App name: %s\n", pm->exeName);
}

int experiment_with_regex() {
    const char* pattern = "*?.ddns.net";
    const char* domain = "my_devil_bad.ddns.net";

    re_t re = re_compile(pattern);
    int match;

    int match_index = re_matchp(re, domain, &match);
    if (match_index == -1) {
        printf("Nope\n");
    }

    printf("Good\n");

    return 0;
}

int examples_main() {
    //return experiment_with_regex();
    //return example1();
    //return example2();
}
