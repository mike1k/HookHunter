# HookHunter
Analyze patches in a process for investigation or repairment purposes.

# Details

HookHunter is a multi-purpose Windows tool that can search a target process in order to find patches and hooks, then build a report. 

In addition, HookHunter is also capable of following generic hooks to their final destination, making it convenient to simply run the tool and know exactly where specific hooks land.

HookHunter also allows a few other options.
* The `mod` argument allows specified modules to be scanned. By default, HookHunter searches the entire set of loaded modules.
* The `dump` argument allows HookHunter to spit out the patched and unpatched variants of a modified image, making it simple to throw the binary into a disassembler for further analysis.
* The `pecheck` argument tells HookHunter to read a custom image's imports (usually a DLL), and alert you if you're using an import that the process is currently hooking.
* The `heal` argument tells HookHunter to begin repairing known patches and hooks to their original variant (be wary of using this option on X86, see notes in Main/etc).
* The `verbose` argument allows explicit logging of HookHunter's current scan.

# Usage
```
Usage:  hookhunter
  -proc         (required) process name/process id
  -mod:         (optional) names of modules to check (or all if none specified).
  -dump:        (optional) dumps patched and unpatched modules for further investigation.
  -pecheck:     (optional) path to a file to alert if any imports the executable uses are being modified.
  -heal:        (optional) repair all modifications to the target binary to the original byte code.
  -verbose:     (optional) log redundant messages associated with HookHunter's scanning
```

# Examples

![CSGO](https://i.imgur.com/p0CyVfe.png)
![DESTINY2](https://i.imgur.com/l6FSUUk.png)
![FIREFOX](https://i.imgur.com/Oxi29mK.png)

# Dependencies
* [Zydis](https://github.com/zyantific/zydis)
* [spdlog](https://github.com/gabime/spdlog)
* [pepp](https://github.com/mike1k/pepp)

