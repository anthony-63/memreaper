package main

import "core:os"
import "core:fmt"
import "color"

import "procfs"

MemReaper :: struct {
    handle: procfs.Process,
    commands: []Command(MemReaper)
}

cmd_init :: proc(reaper: ^MemReaper, args: []string) {
    procfs.refresh_process(&reaper.handle)

    fmt.printfln("%s %s", color.dim("Connected to process:"), color.green(reaper.handle.status.cmdline))
}

cmd_quit :: proc(reaper: ^MemReaper, args: []string) {
    os.exit(0)
}

cmd_help :: proc(reaper: ^MemReaper, args: []string) {
    max_cmd_len := 0
    for cmd in reaper.commands {
        if len(cmd.cmd) > max_cmd_len {
            max_cmd_len = len(cmd.cmd)
        }
    }
    
    for cmd in reaper.commands {
        if cmd.cmd == "init" {
            continue
        }

        padding := max_cmd_len - len(cmd.cmd) + 2
        spaces := make([]u8, padding)
        defer delete(spaces)
        for i in 0..<padding do spaces[i] = ' '
        
        fmt.printf("    %s%s%s\n", 
            color.green(cmd.cmd),
            string(spaces),
            color.dim(cmd.desc))
    }
}