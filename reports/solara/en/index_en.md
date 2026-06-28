# RE // SolaraBootstrapper.exe
---

* Main executable file: **BootstrapperNew.exe**
* File size: **8.26 MB (8467 KB)**
* SHA256: **bbc1e249b5d1212db61e5fee3a63ce614388827bd429cf06dba7699f586abf27**
* MD5: **aa7a86cceb8f870b1ada478c05df80f5**
* Packer: **Custom**
* Compiler: **RustC (Rust)**
* Entropy: **7.26~ (sharp drop to 2.1)**
* Type: **Dropper**

* Drop file: **6610761ea14b.exe** (**csrss.exe**)
* File size: **1.03 MB (1057 KB)**
* SHA256: **007c9981ae0981dc54d4d05715ff1371bd0baf9ebf5ec22da4e12a12a408dff0**
* MD5: **8c62c25ec20e5092d7a1ce349b03ea17**
* Language: **C# (.NET)**
* Entropy: **7.2~**
* Type: **Stealer**

#### Tools used during the analysis:
---
* Static analysis: **IDA Pro, dnSpy, HxD**
* Dynamic analysis: **dnSpy, ProcessHacker, FakeNet-NG**

#### Project structure:
---
* Folders: **autoexec, Solara, workspace**
* Executable files: **SolaraBootstrapper.exe, SLaunch.exe, Solara.exe**

#### Technical Analysis:
---
This sample was discovered on YouTube, distributed under the guise of "cheats roblox".

The main executable dropper deploys a payload into the following directory: **C:\Users\User\AppData\Local\Temp**

The dropped file disguises itself as a critical Windows system process: **csrss.exe** (*Client/Server Runtime Subsystem*).

Initially, **SolaraBootstrapper.exe** was analyzed using static methods. The following section from `.rdata` stands out:

```x86asm
.rdata:0000000140022568 unk_140022568 db 7 ; DATA XREF: sub_140001000+64B
.rdata:0000000140022569 db 5Bh ; [ 
.rdata:000000014002256A db 4Ch ; L 
.rdata:000000014002256B db 4Fh ; O 
.rdata:000000014002256C db 47h ; G 
.rdata:000000014002256D db 5Dh ; ] 
.rdata:000000014002256E db 20h 
.rdata:000000014002256F db 5Bh ; [
.rdata:0000000140022570 db 0C0h 
.rdata:0000000140022571 db 2 
.rdata:0000000140022572 db 5Dh ; ]"
```

The malware implements an internal state machine that logs its execution progress into a specific format:
```log
[LOG] [NUM?] content
```

During dynamic monitoring, the corresponding active log file was located in the **C:\ProgramData** directory:
* File name: **svc_8f123950.log**
* Content: 
```log
[LOG] [1782625697] state.junk
[LOG] [1782625697] state.payload
[LOG] [1782625697] state.payload.decrypted
[LOG] [1782625697] state.load.start
[LOG] [1782625697] state.load.done
[LOG] [1782625697] state.exec.start
```
The logs confirm that the loader monitors encryption stages and payload initialization. The value `1782625697` serves as a Unix timestamp or unique session identifier to track the installation lifecycle.

The assembly layout also reveals standard JSON formatting routines:
```x86asm
mov rcx, [rbx]
mov r9, [rbx+8]
lea rax, asc_14018DDA8 ; " {\n"
mov r14, r8
mov r8d, 3
mov r15, rdx
mov rdx, rax 
call qword ptr [r9+18h] 
mov rdx, r15 
mov r8, r14 
mov r14b, 1 
test al, al 
jnz loc_140004F01 
mov r12, rdx 
mov r15, r8 
movzx r8d, al 
xor r8, 3
lea rcx, asc_14018EB1E ; ", " 
lea rdx, asc_14018EDEE ; " { "
test al, al 
cmovnz rdx, rcx
mov rcx, [rbx]
mov rax, [rbx+8]
call qword ptr [rax+18h]
test al, al
jnz short loc_140004F01
```

During the execution of the dropped payload, dnSpy captured an invocation of `System.Management.dll`. The stealer utilizes WMI queries to harvest hardware profiles (CPU architecture, GPU model) to compile a hardware ID (HWID) and flag potential virtual analysis environments:

```dnspy
(CLR v4.0.30319: 6610761ea14b.exe): Loaded 'C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System.Management\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Management.dll'.
```

Furthermore, the integration of `System.Web.Extensions.dll` introduces the `JavaScriptSerializer` class. This confirms JSON structure generation, maping harvested endpoint parameters before exfiltration:

```json
{
  "computer": "DESKTOP-PC",
  "cpu": "Intel"
}
```

#### Anti-Analysis & Anti-Sandbox Mechanisms:
The executable incorporates aggressive environment evasion. Prior to full execution, it verifies if it is trapped inside sandboxes or hypervisors (**Hyper-V, qemu**). Memory scanning reveals hardcoded string checks looking for active processes of reverse-engineering tools, sniffers, and automated lab accounts:

```text
x32dbg, x64dbg, windbg, ollydbg, dnspy, immunity debugger, hyperdbg, ida, ida64, cheatengine, procmon, wireshark, fiddler, processhacker, hxd, charles, burp, burpsuite, postman, mitmproxy, zap, owasp zap, proxyman, httpdebugger
```
```text
Default Sandbox Users/Hosts: WALKER, WALKER-PC, John, JOHN-PC, Abby, Bruno, george
```

Geolocation filtering is handled via JSON queries to `http://ip-api.com/json/`. The stealer validates the victim's region and network stability before initializing network channels to the primary command-and-control infrastructure.

```text
soft.CSharp ru/http://ip-api.com/json/ GET !application/json country country
```

#### Command & Control (C2):
---
Based on the inclusion of `System.Web.Extensions.dll` and `JavaScriptSerializer`, data transmission relies on HTTP/HTTPS POST requests carrying JSON payloads. Due to intense Control Flow obfuscation, the definitive destination gate URL was not uncovered at the time of this evaluation.

## Conclusion:
---
The investigated sample is classified as a multi-stage dropper combining a Rust execution envelope with a core .NET (C#) data-theft module. It features robust evasion routines, runtime signature checking, and modular payload deployment.
