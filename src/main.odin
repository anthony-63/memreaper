package main

import "core:fmt"
import "core:os"
import "core:strconv"
import "core:strings"

import "color"

import procfs "procfs"

Config :: struct {
    pid: uint,
}

print_usage :: proc(program_name: string) {
    fmt.printf("Usage: %s <pid>\n", program_name)
    fmt.printf("  pid: Process ID to analyze\n")
}

parse_args :: proc() -> (Config, bool) {
    args := os.args
    
    if len(args) < 2 {
        fmt.eprintln("Error: Missing required argument")
        print_usage(args[0])
        return {}, false
    }
    
    if len(args) > 2 {
        fmt.eprintln("Error: Too many arguments")
        print_usage(args[0])
        return {}, false
    }
    
    if args[1] == "-h" || args[1] == "--help" {
        print_usage(args[0])
        return {}, false
    }
    
    pid_str := args[1]
    pid, ok := strconv.parse_uint(pid_str)
    if !ok {
        fmt.eprintf("Error: Invalid PID '%s'. Must be a valid integer.\n", pid_str)
        return {}, false
    }
    
    if pid <= 0 {
        fmt.eprintf("Error: PID must be a positive integer, got %d\n", pid)
        return {}, false
    }
    
    return Config{pid = pid}, true
}


main :: proc() {
    config, ok := parse_args()
    if !ok {
        os.exit(1)
    }
    
    process := procfs.open_process(config.pid)

    cmds := []Command(MemReaper){
        cmd("init", "", cmd_init),
        cmd("maps", "display memory maps in the current program", cmd_maps),
        cmd("scan", "scan for value, usage: scan <type> <value>, ex. scan i32 12, scan bytes \"3a 53 2a\"", cmd_scan),
        cmd("next", "rescan and filter results, usage: next condition <value>, ex. next exact 12, next increased", cmd_next),
        cmd("help", "show this message", cmd_help),
        cmd("quit", "quit memreaper", cmd_quit),
    }

    scanner, err := scanner_create(process.pid)
    if err != .NONE {
        fmt.eprintln(color.red("Failed to create memory scanner"), color.bright_magenta(fmt.tprint(err)))
        return
    }
    defer scanner_destroy(scanner)

    reaper := MemReaper {
        handle = process,
        commands = cmds,
        scanner = scanner,
    }

    run_cli(cmds, &reaper)
}