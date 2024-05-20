#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>


// Library pmps.h
#include "pmps.h"




int main(int argc, char* argv[]) {

    pm_t* pm = NULL;

    if (argc > 2) {
        // If there are more than 2 command-line arguments, use them directly
        pm = CreateProcessMatcher(argv[1]);
        pm = GetProcessHandleByName(pm, argv[2]);
        if (pm == NULL) {
            printf("[-] Error while getting process handle by name\n");
            return 1;
        }
    }
    else {
        // If there are not enough command-line arguments, prompt the user for input
        char regex[4096];
        char process_name[4096];

        printf("=====================================\n");
        printf("This tool is intended to search for null-terminated text buffers into a process's memory using regex.\n");
        printf("Usage:\n");
        printf("   %s <regex> <process_name>(ended with .exe)\n\n", argv[0]); // Display usage based on program name
        printf("If no arguments are provided, the tool will prompt for input.\n");
    start:
        printf("[?] Process ended with .exe: ");
        scanf("%s", process_name);
        printf("[?] Regex: ");
        scanf("%s", regex);

        pm = CreateProcessMatcher(regex);
        pm = GetProcessHandleByName(pm, process_name);
        if (pm == NULL) {
            printf("[-] Error while getting process handle by name\n");
            return 1;
        }
        printf("\n");

        // Enable virtual terminal processing for colored output
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }

    // At this point, pm should have the process handle ready for searching
    printf("Start searching...\n\n");

    // Continue with the search functionality

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