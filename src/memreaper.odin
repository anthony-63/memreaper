package main

import "core:os"
import "core:fmt"
import "core:strconv"

import "color"

import "procfs"

MemReaper :: struct {
    handle: procfs.Process,
    scanner: ^Memory_Scanner,
    commands: []Command(MemReaper)
}

cmd_init :: proc(reaper: ^MemReaper, args: []string) {
    procfs.refresh_process(&reaper.handle)

    fmt.printfln("%s %s", color.dim("Connected to process:"), color.green(reaper.handle.status.cmdline))
}

@(private="file")
parse_scan_value :: proc(t: string, v: string) -> (val: Scan_Value, ok: bool) {
    switch t {
        case "i32": return Scan_Value(i32(strconv.parse_int(v) or_return)), true
        case "i64": return Scan_Value(i64(strconv.parse_int(v) or_return)), true
        case "f32": return Scan_Value(f32(strconv.parse_f32(v) or_return)), true
        case "f64": return Scan_Value(f64(strconv.parse_f64(v) or_return)), true
        case "string": return Scan_Value(v), true
        // case "bytes": return Scan_Value(v), true
        case: fmt.eprintfln("%s%s", color.dim(color.red("Failed to parse type: ")), color.red(t))
    }

    return {}, false
}

@(private="file")
print_scan_results :: proc(scanner: ^Memory_Scanner, max_results := 20) {
    if len(scanner.results) == 0 {
        fmt.printf("  %s\n", color.dim("No results found"))
        return
    }
    
    count_color := len(scanner.results) > 100 ? color.bright_red : len(scanner.results) > 10 ? color.yellow : color.green
    fmt.printf("  Found %s result%s\n", 
        count_color(fmt.tprintf("%d", len(scanner.results))), 
        len(scanner.results) == 1 ? "" : "s")
    
    if len(scanner.results) > max_results {
        fmt.printf("  %s\n", color.dim(fmt.tprintf("Showing first %d:", max_results)))
    }
    
    fmt.printf("\n")
    
    display_count := min(max_results, len(scanner.results))
    for i in 0..<display_count {
        result := scanner.results[i]
        print_single_result(result, i+1)
    }
    
    if len(scanner.results) > max_results {
        remaining := len(scanner.results) - max_results
        fmt.printf("  %s\n", color.dim(fmt.tprintf("... and %d more", remaining)))
    }
}

@(private="file")
print_single_result :: proc(result: Scan_Result, index: int) {
    addr_str := color.cyan(format_address(result.address))
    value_str := format_scan_value(result.value)
    
    fmt.printf("  %s  %s\n", addr_str, value_str)
}

@(private="file")
format_address :: proc(addr: u64) -> string {
    return fmt.tprintf("0x%016x", addr)
}

@(private="file")
format_scan_value :: proc(value: Scan_Value) -> string {
    switch val in value {
    case i32:
        return color.bright_white(fmt.tprintf("%d", val))
    case i64:
        return color.bright_white(fmt.tprintf("%d", val))
    case f32:
        return color.bright_magenta(fmt.tprintf("%.6g", val))
    case f64:
        return color.bright_magenta(fmt.tprintf("%.6g", val))
    case []u8:
        return color.yellow(format_bytes(val))
    case string:
        return color.green(fmt.tprintf("\"%s\"", val))
    }
    return color.red("<?>")
}

@(private="file")
format_bytes :: proc(bytes: []u8) -> string {
    if len(bytes) == 0 do return "[]"
    
    if len(bytes) <= 8 {
        result := "["
        for i, b in bytes {
            if i > 0 do result = fmt.tprintf("%s ", result)
            result = fmt.tprintf("%s%02x", result, b)
        }
        return fmt.tprintf("%s]", result)
    }
    
    result := "["
    for i in 0..<min(4, len(bytes)) {
        if i > 0 do result = fmt.tprintf("%s ", result)
        result = fmt.tprintf("%s%02x", result, bytes[i])
    }
    
    if len(bytes) > 4 {
        result = fmt.tprintf("%s...] (%d bytes)", result, len(bytes))
    } else {
        result = fmt.tprintf("%s]", result)
    }
    
    return result
}

cmd_scan :: proc(reaper: ^MemReaper, args: []string) {
    procfs.refresh_process(&reaper.handle)
    
    if len(args) != 2 {
        fmt.eprintln(color.red("Invalid usage of scan"))
    }

    val, ok := parse_scan_value(args[0], args[1])
    if !ok {
        return
    }

    result_count, err := scanner_scan(reaper.scanner, reaper.handle.maps, val)
    if err != .NONE {
        fmt.eprintln(color.red("Error scanning:"), color.bright_red(fmt.tprint(err)))
    }

    print_scan_results(reaper.scanner)
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