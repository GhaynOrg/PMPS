<div align="center">
    <h1 style="font-size:25px;"><strong>Process Memory Pattern Scanner (PMPS)🔎</strong></h1>
      <br/>

  <p><i>C/C++ library and tool for scanning a process's memory space on Windows to find regex string patterns.</i></p>
  <br/>

   <img src="Images/img1.png" width="90%"/>
   <br/>
   <br/>
<p>It searches the process memory space page by page until it finds a block of memory that matches your regex. Then, it returns the entire page containing the matched string.</p>
  <br />
</div>

Table Of Content
---
<!--ts-->
- [Table Of Content](#table-of-content)
- [Library and Tool](#library-and-tool)
- [Why?](#why)
- [Examples for using tool and library](#examples-for-using-tool-and-library)
  - [#1 Finding Sensitive Messages And Metadata (Tool)](#1-finding-sensitive-messages-and-metadata-tool)
  - [#2 Detecting debuggers (Library)](#2-detecting-debuggers-library)
  - [#3 Malware Detection (Library)](#3-malware-detection-library)
- [Documentation](#documentation)
  - [Header file docs:](#header-file-docs)
  - [Details docs:](#details-docs)
  - [Create the process matcher](#create-the-process-matcher)
  - [Functions to find process handle](#functions-to-find-process-handle)
  - [Searching for patterns in memory](#searching-for-patterns-in-memory)
  - [Cleanup Process Matcher](#cleanup-process-matcher)
- [More Examples](#more-examples)
- [TODO](#todo)
- [Dependency](#dependency)
- [Author](#author)
- [Misc](#misc)
  - [Tools](#tools)
  - [Inspiration](#inspiration)
- [LICENSE](#license)
<!--te-->

<br />

## Library and Tool
To utilize the memory searching approach in this project, you will be provided with two resources:
<br/>
- Library: You can import these files into your C/C++ project to build applications and programs that leverage the memory searching approach.
> Import [pmps.h](/pmps.h), [re.h](/re.h) [pmps.c](/pmps.c) and [re.c](/re.c) in your project then include pmps.h and read the docs to find what you need to use.

> 🟡 I will port it to vcpkg later, after ensuring it is stable and has standard features.

- Simple Tool: A pre-built binary that requires two inputs: a process name and a pattern to begin searching.
> You can download the pre-built binary of the tool from [here](https://github.com/GhaynOrg/PMPS/releases/tag/Tool).

## Why?
At first glance, this idea may seem useless to some of you, but its beauty will become evident through the following examples.


## Examples for using tool and library

### #1 Finding Sensitive Messages And Metadata (Tool)
If you choose to use this tool, you can pass your regex to search for messages in certain apps, such as Discord.

Suppose a message like the one below has been sent in Discord:

![Discord message](Images/img2.png)

As you can see, the text says "Yeah my password: Abc123123Abc".

You can create a regex pattern `my password:\s*` and use it with the tool:

```
=====================================
This tool is intended to search for null-terminated text buffers in a process's memory using regex.
[?] Process: discord.exe
[?] Regex: my password:\s*
```
<br/>

then search in the output that the tool provides:

![Tool output](Images/img3.png)

the output is extensive, but you can see that the token `Authorization` is exposed here, which is really dangerous!

below you can see the message and some metadata. Even if you protect all disk storage on your device. The memory still contains a lot of sensitive data.

![Sensitive data in memory](Images/img4.png)

There's no need to dump the entire memory. Just examining one page, 4KB of memory, one memory block, can reveal this data.

### #2 Detecting debuggers (Library)
If you've put in a lot of effort to create a program, you certainly wouldn't want it to be run in an environment where debuggers could be used to crack it. A very common method to prevent this is to search for processes by process name or window name. However, crackers can easily bypass this by changing the window or process names.
<br/>
here also shine the idea of finding pattren strings in memory you can code your program with the library pmps.h to detect debuggers by search in every process until it find a match.
<br/>
<br/>
Exmaple code using the library:
```c
#include <pmps.h>

int main(){
  const char* ida_patters = "[Ii][Dd][Aa] [Ff]reeware\s*";
  pm_t* pm = PMSearchAllForMatch(ida_patters, TRUE);
  printf("App name: %s\n", pm->exeName);
}
```
output:
```
App name: ida64.exe
```
> ⚠ This method does not depend on the file name; it searches all process memory spaces to find a match.

> ℹ For more details on the function used, please refer to the documentation section.

as you can see we successfully find it without searching for process name or anything just a simple pattern and diging in memory.

### #3 Malware Detection (Library)
I can't come up with something fancy, but it's all about patterns. For example, using a `no-ip.com` domain, which is usually in the format `some-name.ddns.net`, could be a significant red flag.

Example code using the library:
> ❓ I assume that you already have a way to detect malware and you already have the PID.

```c
#include <pmps.h>
int main() {
    const char* ddns_pattern = "*?.ddns.net";
    pm_t* pm = CreateProcessMatcher(ddns_pattern);
    // Assume:
    DWORD pid = my_magic_function_to_detect_malware_pid();
    
    if (GetProcessHandleByPID(pm, pid) == NULL) {
        printf("Cannot open process handle.");
        return 1;
    }
    char* matchedString  = PMFindMatchBlock(pm);
    if (matchedString  == NULL) {
        printf("No DDNS.net domain found, maybe it is something else.");
        return 1;
    }
    printf("DDNS.net domain found: %s", matchedString);
    return 0;
}
```
even if the malware has obfuscated the domain name and hardcoded it into the binary, it will need to deobfuscate it at runtime, and then you will find the pattern.


---
> This is just a few examples to inspire you about how this library may be used. I think many of you now know the potential of utilizing memory searching to find valuable information!


## Documentation

### Header file docs:
```c
/*
* Create a new instance of Process Matcher for pattern scanning.
*
* @param pattern Regex pattern to scan for.
*
* @return Pointer to a Process Matcher instance.
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
* @param pm Initialized instance of Process Matcher type data using `CreateProcessMatcher`.
* @param process_name Process name ending with `.exe`.
* @return Pointer to the same `pm` parameter, including the process handle if found, or NULL on failure.
*/
pm_t* GetProcessHandleByName(pm_t* pm, char* process_name);

/*
* This function yields the first pattern it finds but saves the state in the Process Matcher type data you pass as parameter, meaning you can call it to find other blocks one by one. Note: The return value indicates whether a match was found. To access the full match data, use the fields within the pm_t structure, as they are updated with each found block.

* @param pm Initialized instance of Process Matcher type data using `CreateProcessMatcher` and having the process handle using either `GetProcessHandleByPID` or `GetProcessHandleByName`.

* @return Pointer of type char that points to the `stringBuffer` field inside the pm_t structure, or NULL when there are no more matches or a match cannot be found.
*/
char* PMFindMatchBlock(pm_t* pm);

```

### Details docs:
Process Memory Pattern Scanner (PMPS)🔎

PMPS uses the Windows API function `VirtualQueryEx` to fetch the memory blocks of a specific process. It searches within the process's virtual memory space, which starts at a base address of 0 and extends to the end of the virtual memory. This means that it does not search within the physical memory directly. The search iterate in pages `4KB` at a time. This page size was chosen because it provides optimal alignment for memory, and in my tests, I did not encounter any issues with data cut.
\
Look at this illustration of what I mean:
\
![Memory search issue](Images/img5.png)

> 🔴 This does not mean at all that there will be no cuts in data when searching by page, but this is the best approach that I find this library could use right now and later I will add a method that allow to search by any size.

So that is how the search works. Now, let's talk about some functions in detail.

### Create the process matcher
The first step in searching a process's memory is to create an instance of the `pm_t` structure, which will save the state of your search and provide the necessary data. To create an instance of pm_t, use the following function:
\
`pm_t* CreateProcessMatcher(char* pattern);`
\
The function requires you to pass a regex pattern, and it returns an initialized pointer to a pm_t instance.
\
**Example useage:**
```c
#include <pmps.h>

int main(){
  // Create process matcher instance
  pm_t* pm = CreateProcessMatcher("[Hh]ey");

  // ...
  // Step to the next process
}
```

> **ℹ Important: Please note that the regex expressions should follow the rules provided by the <a src="https://github.com/kokke/tiny-regex-c">@kokke/tiny-regex-c</a> library, as we use this library as a dependency to parse regex patterns. Make sure to check their documentation and adhere to their implementation rules for regex.**
---
### Functions to find process handle
After creating a pm_t instance, you must obtain the handle of the process whose memory you want to search. There are two functions available for this purpose: GetProcessHandleByPID and GetProcessHandleByName.
\
As their names suggest:

- `pm_t* GetProcessHandleByName(pm_t* pm, char* process_name);`\
This function finds the process handle by its name.
- > **⚠ The name should end with .exe (e.g. my_proc.exe).**

- `pm_t* GetProcessHandleByPID(pm_t* pm, DWORD pid);`\
This function finds the process handle by its process ID (PID).

> Both functions return a pointer to the same pm_t instance that you pass as a parameter. If they fail, they return NULL.

**Example useage:**
```c
#include <pmps.h>

int main() {
    // Create process matcher instance
    pm_t* pm = CreateProcessMatcher("[Hh]ey");

    // Get process handle

    // By name
    if (GetProcessHandleByName(pm, "my_proc.exe") == NULL) {
        // Couldn't find the process handle
        return 1;
    }

    /* ======== OR ======== */

    // By PID
    if (GetProcessHandleByPID(pm, 1234) == NULL) {
        // Couldn't find the process handle
        return 1;
    }

    /*=-=-=-=-=-=Extra=-=-=-=-=-=*/
    // If you have the handle, better set the handle manually
    HANDLE pHandle = /*your magic*/;
    pm->pHandle = pHandle;

    // ...
    // Step to the next process
}

```

### Searching for patterns in memory
Now you can start finding the string patterns. For that, use the function:
\
`char* PMFindMatchBlock(pm_t* pm);`
\
This function searches until it finds a page/block of memory containing your pattern, then returns the address. You can use the return value (a char*), but it just points to the `stringBuffer` field inside the `pm_t*` structure that you pass as a parameter or returns NULL on failure. Therefore, you can only depend on that structure to get the data each time you call PMFindMatchBlock. There is much to say about this, so pay close attention.
\
**Example useage:**
```c
#include <pmps.h>

int main() {
    // Create process matcher instance
    pm_t* pm = CreateProcessMatcher("[Hh]ey");
    
    // ...
    
    // Find match
    char* matchedBuffer = PMFindMatchBlock(pm);

    // If null, this means no match has been found at all
    if (matchedBuffer == NULL) {
        printf("No match has been found in the entire process's memory\n");
        return 1;
    }

    // If a match has been found, that doesn't mean it's the only match.
    // There may be others, but it yields when it finds one.
    // To continue searching, just call it again with the same `pm_t*`
    // because the state is saved in it:
    matchedBuffer = PMFindMatchBlock(pm);

    // If null, this means no more matches have been found.
    if (matchedBuffer == NULL) {
        printf("No more matches have been found in the rest of the process's memory\n");
        return 1;
    }

    // You can access the whole string buffer that has your match
    // using your variable, in this case, matchedBuffer:
    printf("Matched String: %s\n", matchedBuffer);

    // Or you can access it using the field `stringBuffer`:
    printf("Matched String: %s\n", pm->stringBuffer);

    // You can access the entire memory dump page that has the match:
    for (int i = 0; i < pageSize; i++) {
        printf("%20X ", pm->memDumpBuffer[i]);
    }
    printf("\n");

    // You also have the offsetOfString in the memory dump, which tells you
    // where the first character is in the memory dump:
    char firstChar = pm->memDumpBuffer[pm->offsetOfString];

    //...
    // After all that, you have to clean up
}


```
The library does not allocate and free memory for each search. Instead, there is a fixed heap-allocated size (Page Size 4KB) for both `pm->stringBuffer` and `pm->memDumpBuffer` for better performance. This means that at every search, these buffers are cleared and new data is written to them. If you need to use the data elsewhere, you should allocate space for it yourself.
\

After all that you have to cleanup the Process Matcher.

### Cleanup Process Matcher
Simply use the function
\
`void CleanupProcessMatcher(pm_t* pm);`
\
to clean up the `pm_t*`

**Example useage:**
```C
int main() {
    // Create process matcher instance
    pm_t* pm = CreateProcessMatcher("[Hh]ey");

    // Clean up
    CleanupProcessMatcher(pm);
}
```

## More Examples
See [examples.c](/examples.c)

## TODO
The code contains various TODOs and some sections where I might have used incorrect or not written very carefully. Please don't hesitate to improve my code and teach me about things that I might have missed. Thanks in advance.

Some TODOs:
> The documentation section should be reviewed to improve the details it provides and to enhance the clarity of the English used in it. (I'm not a native speaker)

> Adding a function that allow the user to set the size of the search, offering more flexibility than just sticking to a fixed page size.

> Include useful data about the search process in `pm_t*`.


## Dependency

The project depend on the library [@kokke/tiny-regex-c](https://github.com/kokke/tiny-regex-c) for parsing regex. Thanks to [@kokke](https://github.com/kokke/) for creating this wonderful library. Please note that the project uses a specific version of their code to avoid mismatches when they update their library. Import the files [re.c](/re.c) and [re.h](/re.h) from our repository.

## Author
This project was created by @justalghamdi under [Ghayn organization](https://github.com/ghaynorg).

You can find more here:
\
[LinkTree @justalghamdi](https://linktr.ee/justalghamdi)
\
or 
\
contact@v0id.me | anything[at]v0id.me will probably drop at my inbox ;)

## Misc

### Tools
IDE: `Visual Studio 2022`
\
Screenshots: `ShareX`
\
Diagram: `Draw.IO`

### Inspiration

I've seen this method used in many malicious softwares to steal data, and I've provided an example for that. However, I'm always fascinated by its power, because no matter how well you hide data, the memory can have flaws and patterns that can identify the data you try to hide. Just like any method, someone has to discuss and develop it to make it easier to use, and I hope I can contribute to that effort.

---

Some repositories that utilize memory searching for malicious purposes:

- [ZeroMemoryEx/DeadLight](https://github.com/ZeroMemoryEx/DeadLight)

They use `MiniDumpWriteDump` to dump the entire memory to a file on disk and then read all of it to try to find Discord tokens. Dumping the entire memory to file and then loading it into your process memory is very memory-intensive. For example, an app like Discord may have a memory dump size of 255 MB, making this process very slow for dumping, loading, and searching.
\
(Note: I couldn't find any other repositories that I remember; perhaps they have been deleted.)

---

Additionally, I've seen this feature used in the program [Process Hacker](https://processhacker.sourceforge.io/), which also helped inspire and motivate me to develop this library.

---

Special mentions to some colleagues that I've got Inspired from:


\
Instagram: [@vpw3](https://www.instagram.com/vpw3)
\
Instagram: [@kkk0](https://www.instagram.com/kkk0)

## LICENSE

For our project PMPS, the `LICENSE` is [The 3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

For the dependency [@kokke/tiny-regex-c](https://github.com/kokke/tiny-regex-c), the `LICENSE` is [The Unlicense](https://unlicense.org/).