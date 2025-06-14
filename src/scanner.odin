package main

import "core:os"
import "core:fmt"
import "core:mem"
import "core:slice"
import "core:strings"
import "core:strconv"

import "color"
import "procfs"

foreign import libc "system:c"

foreign libc {
    process_vm_readv :: proc(pid: i32, local_iov: ^IOVec, liovcnt: u64, remote_iov: ^IOVec, riovcnt: u64, flags: u64) -> i64 ---
    ptrace :: proc(request: i32, pid: i32, addr: rawptr, data: rawptr) -> i64 ---
    waitpid :: proc(pid: i32, status: ^i32, options: i32) -> i32 ---
}

IOVec :: struct {
    iov_base: rawptr,
    iov_len:  u64,
}

PTRACE_ATTACH :: 16
PTRACE_DETACH :: 17
PTRACE_PEEKDATA :: 2
PTRACE_POKEDATA :: 5

Scan_Value :: union {
    i32,
    i64,
    f32,
    f64,
    []u8,
    string,
}

Scan_Condition :: enum {
    UNCHANGED,
    CHANGED,
    INCREASED,
    DECREASED,
    EXACT,
}

Scan_Result :: struct {
    address: u64,
    value:   Scan_Value,
}

Memory_Scanner :: struct {
    pid:     procfs.Pid,
    results: [dynamic]Scan_Result,
}

Scanner_Error :: enum {
    NONE,
    INVALID_PID,
    MEMORY_ERROR,
    PERMISSION_DENIED,
    PROCESS_NOT_FOUND,
}

scanner_create :: proc(pid: procfs.Pid, allocator := context.allocator) -> (^Memory_Scanner, Scanner_Error) {
    context.allocator = allocator
    
    scanner := new(Memory_Scanner)
    scanner.pid = pid
    scanner.results = make([dynamic]Scan_Result)
    
    return scanner, .NONE
}

scanner_destroy :: proc(scanner: ^Memory_Scanner) {
    if scanner == nil do return
    
    for &result in scanner.results {
        if bytes, ok := result.value.([]u8); ok {
            delete(bytes)
        }
    }
    
    delete(scanner.results)
    free(scanner)
}

read_process_memory :: proc(pid: procfs.Pid, local_buf: []u8, remote_addr: rawptr) -> (int, Scanner_Error) {
    local_iov := IOVec{
        iov_base = raw_data(local_buf),
        iov_len = u64(len(local_buf)),
    }
    
    remote_iov := IOVec{
        iov_base = remote_addr,
        iov_len = u64(len(local_buf)),
    }
    
    bytes_read := process_vm_readv(i32(pid), &local_iov, 1, &remote_iov, 1, 0)
    
    if bytes_read < 0 {
        return 0, .MEMORY_ERROR
    }
    
    return int(bytes_read), .NONE
}

write_process_memory :: proc(pid: procfs.Pid, data: []u8, remote_addr: rawptr) -> (int, Scanner_Error) {
    if ptrace(PTRACE_ATTACH, i32(pid), nil, nil) == -1 {
        return 0, .PERMISSION_DENIED
    }
    defer ptrace(PTRACE_DETACH, i32(pid), nil, nil)
    
    status: i32
    if waitpid(i32(pid), &status, 0) == -1 {
        return 0, .PROCESS_NOT_FOUND
    }
    
    addr := uintptr(remote_addr)
    bytes_written := 0
    word_size := size_of(i64)
    
    for bytes_written < len(data) {
        word_addr := addr & ~uintptr(word_size - 1)
        offset_in_word := addr & uintptr(word_size - 1)
        bytes_in_this_word := word_size - int(offset_in_word)
        
        if bytes_in_this_word > len(data) - bytes_written {
            bytes_in_this_word = len(data) - bytes_written
        }
        
        word: i64
        if offset_in_word != 0 || bytes_in_this_word != word_size {
            word = ptrace(PTRACE_PEEKDATA, i32(pid), rawptr(word_addr), nil)
        }
        
        word_bytes := transmute([8]u8)word
        copy(word_bytes[offset_in_word:offset_in_word + uintptr(bytes_in_this_word)], 
             data[bytes_written:bytes_written + bytes_in_this_word])
        word = transmute(i64)word_bytes
        
        if ptrace(PTRACE_POKEDATA, i32(pid), rawptr(word_addr), rawptr(uintptr(word))) == -1 {
            break
        }
        
        bytes_written += bytes_in_this_word
        addr += uintptr(bytes_in_this_word)
    }
    
    return bytes_written, .NONE
}

scanner_scan :: proc(scanner: ^Memory_Scanner, maps: []procfs.Procfs_Map_Entry, target: Scan_Value) -> (int, Scanner_Error) {
    for &result in scanner.results {
        if bytes, ok := result.value.([]u8); ok {
            delete(bytes)
        }
    }
    clear(&scanner.results)
    
    for map_ in maps {
        if .Read not_in map_.permissions do continue
        if strings.contains(map_.pathname, "[vdso]") || strings.contains(map_.pathname, "[vsyscall]") {
            continue
        }

        if map_.pathname != "" && map_.pathname[0] != 0 {
            fmt.print(color.dim("\x1b[2KScanning memory region:"), format_module(map_.pathname, map_.permissions), "\r")
        }
        
        scan_region(scanner, map_.start, map_.end, target) or_continue
    }
    
    return len(scanner.results), .NONE
}

scan_region :: proc(scanner: ^Memory_Scanner, start: u64, end: u64, target: Scan_Value) -> Scanner_Error {
    CHUNK_SIZE :: 4096
    buffer: [CHUNK_SIZE]u8
    
    for addr := start; addr < end; addr += CHUNK_SIZE {
        read_size := min(CHUNK_SIZE, int(end - addr))
        buffer_slice := buffer[:read_size]
        
        bytes_read, err := read_process_memory(scanner.pid, buffer_slice, rawptr(uintptr(addr)))
        if err != .NONE || bytes_read != read_size do continue
        
        switch target_val in target {
            case i32:
                scan_for_i32(scanner, addr, buffer_slice, target_val)
            case i64:
                scan_for_i64(scanner, addr, buffer_slice, target_val)
            case f32:
                scan_for_f32(scanner, addr, buffer_slice, target_val)
            case f64:
                scan_for_f64(scanner, addr, buffer_slice, target_val)
            case []u8:
                scan_for_bytes(scanner, addr, buffer_slice, target_val)
            case string:
                scan_for_string(scanner, addr, buffer_slice, target_val)
        }
    }
    
    return .NONE
}

scan_for_i32 :: proc(scanner: ^Memory_Scanner, base_addr: u64, buffer: []u8, target: i32) {
    for i := 0; i <= len(buffer) - size_of(i32); i += size_of(i32) {
        value := (^i32)(raw_data(buffer[i:]))^
        if value == target {
            result := Scan_Result{
                address = base_addr + u64(i),
                value = value,
            }
            append(&scanner.results, result)
        }
    }
}

scan_for_i64 :: proc(scanner: ^Memory_Scanner, base_addr: u64, buffer: []u8, target: i64) {
    for i := 0; i <= len(buffer) - size_of(i64); i += size_of(i64) {
        value := (^i64)(raw_data(buffer[i:]))^
        if value == target {
            result := Scan_Result{
                address = base_addr + u64(i),
                value = value,
            }
            append(&scanner.results, result)
        }
    }
}

scan_for_f32 :: proc(scanner: ^Memory_Scanner, base_addr: u64, buffer: []u8, target: f32) {
    for i := 0; i <= len(buffer) - size_of(f32); i += size_of(f32) {
        value := (^f32)(raw_data(buffer[i:]))^
        if value == target {
            result := Scan_Result{
                address = base_addr + u64(i),
                value = value,
            }
            append(&scanner.results, result)
        }
    }
}

scan_for_f64 :: proc(scanner: ^Memory_Scanner, base_addr: u64, buffer: []u8, target: f64) {
    for i := 0; i <= len(buffer) - size_of(f64); i += size_of(f64) {
        value := (^f64)(raw_data(buffer[i:]))^
        if value == target {
            result := Scan_Result{
                address = base_addr + u64(i),
                value = value,
            }
            append(&scanner.results, result)
        }
    }
}

scan_for_bytes :: proc(scanner: ^Memory_Scanner, base_addr: u64, buffer: []u8, target: []u8) {
    if len(target) == 0 do return
    
    for i := 0; i <= len(buffer) - len(target); i += 1 {
        if slice.equal(buffer[i:i+len(target)], target) {
            bytes_copy := make([]u8, len(target))
            copy(bytes_copy, target)
            
            result := Scan_Result{
                address = base_addr + u64(i),
                value = bytes_copy,
            }
            append(&scanner.results, result)
        }
    }
}

scan_for_string :: proc(scanner: ^Memory_Scanner, base_addr: u64, buffer: []u8, target: string) {
    target_bytes := transmute([]u8)target
    if len(target_bytes) == 0 do return
    
    for i := 0; i <= len(buffer) - len(target_bytes); i += 1 {
        if slice.equal(buffer[i:i+len(target_bytes)], target_bytes) {
            result := Scan_Result{
                address = base_addr + u64(i),
                value = strings.clone(target),
            }
            append(&scanner.results, result)
        }
    }
}

scanner_next_scan :: proc(scanner: ^Memory_Scanner, condition: Scan_Condition, target: ^Scan_Value = nil) -> (int, Scanner_Error) {
    if len(scanner.results) == 0 do return 0, .NONE
    
    new_results := make([dynamic]Scan_Result, 0, len(scanner.results))
    defer if len(new_results) == 0 do delete(new_results)
    
    for &result in scanner.results {
        current_value, read_ok := read_current_value(scanner.pid, result.address, result.value)
        if !read_ok do continue
        defer free_scan_value(current_value)
        
        keep := false
        switch condition {
            case .UNCHANGED:
                keep = scan_values_equal(result.value, current_value)
            case .CHANGED:
                keep = !scan_values_equal(result.value, current_value)
            case .INCREASED:
                keep = scan_value_compare(current_value, result.value) > 0
            case .DECREASED:
                keep = scan_value_compare(current_value, result.value) < 0
            case .EXACT:
                if target != nil {
                    keep = scan_values_equal(current_value, target^)
                }
        }
        
        if keep {
            new_result := Scan_Result{
                address = result.address,
                value = clone_scan_value(current_value),
            }
            append(&new_results, new_result)
        }
        
        free_scan_value(result.value)
    }
    
    delete(scanner.results)
    scanner.results = new_results
    
    return len(scanner.results), .NONE
}

read_current_value :: proc(pid: procfs.Pid, address: u64, old_value: Scan_Value) -> (Scan_Value, bool) {
    switch old in old_value {
        case i32:
            val: i32
            buffer := slice.bytes_from_ptr(&val, size_of(i32))
            _, err := read_process_memory(pid, buffer, rawptr(uintptr(address)))
            return val, err == .NONE
            
        case i64:
            val: i64
            buffer := slice.bytes_from_ptr(&val, size_of(i64))
            _, err := read_process_memory(pid, buffer, rawptr(uintptr(address)))
            return val, err == .NONE
            
        case f32:
            val: f32
            buffer := slice.bytes_from_ptr(&val, size_of(f32))
            _, err := read_process_memory(pid, buffer, rawptr(uintptr(address)))
            return val, err == .NONE
            
        case f64:
            val: f64
            buffer := slice.bytes_from_ptr(&val, size_of(f64))
            _, err := read_process_memory(pid, buffer, rawptr(uintptr(address)))
            return val, err == .NONE
            
        case []u8:
            data := make([]u8, len(old))
            _, err := read_process_memory(pid, data, rawptr(uintptr(address)))
            if err != .NONE {
                delete(data)
                return nil, false
            }
            return data, true
            
        case string:
            data := make([]u8, len(old))
            _, err := read_process_memory(pid, data, rawptr(uintptr(address)))
            if err != .NONE {
                delete(data)
                return nil, false
            }
            return string(data), true
    }
    
    return nil, false
}

scan_values_equal :: proc(a, b: Scan_Value) -> bool {
    switch a_val in a {
        case i32:
            if b_val, ok := b.(i32); ok do return a_val == b_val
        case i64:
            if b_val, ok := b.(i64); ok do return a_val == b_val
        case f32:
            if b_val, ok := b.(f32); ok do return a_val == b_val
        case f64:
            if b_val, ok := b.(f64); ok do return a_val == b_val
        case []u8:
            if b_val, ok := b.([]u8); ok do return slice.equal(a_val, b_val)
        case string:
            if b_val, ok := b.(string); ok do return a_val == b_val
    }
    return false
}

scan_value_compare :: proc(a, b: Scan_Value) -> int {
    #partial switch a_val in a {
        case i32:
            if b_val, ok := b.(i32); ok {
                if a_val < b_val do return -1
                if a_val > b_val do return 1
                return 0
            }
        case i64:
            if b_val, ok := b.(i64); ok {
                if a_val < b_val do return -1
                if a_val > b_val do return 1
                return 0
            }
        case f32:
            if b_val, ok := b.(f32); ok {
                if a_val < b_val do return -1
                if a_val > b_val do return 1
                return 0
            }
        case f64:
            if b_val, ok := b.(f64); ok {
                if a_val < b_val do return -1
                if a_val > b_val do return 1
                return 0
            }
    }
    return 0
}

clone_scan_value :: proc(value: Scan_Value) -> Scan_Value {
    switch val in value {
    case i32, i64, f32, f64:
        return val
    case []u8:
        copy := make([]u8, len(val))
        copy_slice(copy, val)
        return copy
    case string:
        return strings.clone(val)
    }
    return nil
}

free_scan_value :: proc(value: Scan_Value) {
    #partial switch val in value {
    case []u8:
        delete(val)
    case string:
        delete(val)
    }
}