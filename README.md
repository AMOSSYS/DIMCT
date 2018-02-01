# DIMCT
Dirty Inter Module Calls Tracer

Allows tracing inter module calls for a specific module within a Windows process.

### Usage ###

The usage is relatively straightforward: 
1. Run the provided IDAPython script in order to generate a configuration file;
2. Start the monitored process;
3. Run the provided executable with the process PID, the configuration file, and the delay before killing the process;
4. Load the output with the IDAPython script in order to pinpoint which functions have been called;
5. Manually parse the output file if you want more information, e.g 'who called who'.

### Internals ###

Inline hooks are placed in top of any identified function. The hook points toward a logging function, which only logs intermodular calls. Logs are performed in a dedicated memory area, which is periodically read and dumped by the remote process.

It follows this scheme:
<center><img src="/img/dimct_1.png" alt="Figure1" title="DIMCT flow" width="80%" height="80%"/><br/>
**Figure 1: DIMCT flow**
</center>

The reasons why we call this tool "dirty" are the following ones:
1. we do NOT use a shared memory section, the monitoring process keeps reading the remote memory area and wipes it when full (two WriteProcessMemory calls are done, one to wipe the area, the second one to "release" the mutex). We just gave the monitoring process an higher priority than the target process in order to minimize the impact;
2. we do NOT use any Windows API in the logging function, so mutexes are implemented with a `lock cmpxchg` instruction (i.e no OS benefits such as thread priority boosts).

Yeah, that's really dirty, but this actually worked without too much bugs/overhead/drops, so... we keeped it as is. We also did not encounter the need for x64 binaries so actually only x86 processes are handled (the concept remains the same, we will implement it soon, I guess).

The main problems we faced is handling relative instructions while moving our saved instructions. Moving a `SHORT JMP` or a `CALL`, which opcodes are relatives to the current instruction position is not that straightforward, and that's the main reason why we used an IDAPython script.

In order to face this problem and use absolute addresses, we replaced `CALLS` and `JMPS` with `PUSH/RET` instructions, and conditional jumps with their counterparts and `PUSH/RET` instructions. For instance, a `JNZ SHORT <addr>` will be replaced by a `JZ SHORT $+6 / PUSH <addr> / RET`. Those absolute addresses belonging to the module itself are stored relatively to the module base address, and then "relocated" at the hook installation. Absolute addresses are also logged in order to be relocated by the program.

As an example, here are the original function, the configuration file and the final result:
<center><img src="/img/dimct_2.png" alt="Figure1" title="DIMCT trampolines" width="80%" height="80%"/><br/>
**Figure 2: DIMCT trampolines**
</center>

### Improvements ###

TO-DO list:
1. Use a shared memory region;
2. Use system mutexes;
3. x64 support;
4. Performances tuning;
5. Rename DIMCT to QDIMCT (Quite Dirty IMCT).

Disclaimer: we'll probably implement these features when we will face the issues (i.e we don't know when), so feel free to ask/reuse/fork/pull requests :)