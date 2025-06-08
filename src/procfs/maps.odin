package procfs

import "core:fmt"
import "core:os"
import "core:strings"
import "core:strconv"
import "core:bufio"
import color "../../external/odin-color"

Map_Permission :: enum {
    Read,
    Write,
    Execute,
    Shared,
    Private,
}

Map_Permission_Set :: bit_set[Map_Permission]

Map_Entry :: struct {
    start: u64,
    end: u64,

    permissions: Map_Permission_Set,

    offset: u64,

    device: string,
    inode: u64,

    pathname: string,
}

@(private="file")
parse_permissions :: proc(perms_str: string) -> (Map_Permission_Set, bool) {
    perms: Map_Permission_Set
    
    perm_chars := strings.split(perms_str, "")

    for perm in perm_chars {
        switch perm {
            case "r": perms += {.Read}
            case "w": perms += {.Write}
            case "x": perms += {.Execute}
            case "s": perms += {.Shared}
            case "p": perms += {.Private}
            case "-": continue
            case: return {}, false
        }
    }

    return perms, true
}

@(private="file")
parse_map_line :: proc(line: string) -> (Map_Entry, bool) {
    parts := strings.fields(line)
    if len(parts) < 5 do return {}, false
    
    entry: Map_Entry
    addr_parts := strings.split(parts[0], "-")
    if len(addr_parts) != 2 do return {}, false
    defer delete(addr_parts)
    
    if start, ok := strconv.parse_u64(addr_parts[0], 16); ok {
        entry.start = start
    } else {
        return {}, false
    }
    
    if end, ok := strconv.parse_u64(addr_parts[1], 16); ok {
        entry.end = end
    } else {
        return {}, false
    }
    
    if perms, ok := parse_permissions(strings.clone(parts[1])); ok {
        entry.permissions = perms
    } else {
        return {}, false
    }
    
    if offset, ok := strconv.parse_u64(parts[2], 16); ok {
        entry.offset = offset
    } else {
        return {}, false
    }
    
    entry.device = strings.clone(parts[3])
    
    if inode, ok := strconv.parse_u64(parts[4], 10); ok {
        entry.inode = inode
    } else {
        return {}, false
    }
    
    if len(parts) > 5 {
        pathname_parts := parts[5:]
        entry.pathname = strings.clone(strings.join(pathname_parts, " "))
    }
    
    return entry, true
}

read_procfs_maps :: proc(pid: Pid) -> [dynamic]Map_Entry {
    maps: [dynamic]Map_Entry

    maps_file, err := os.open(fmt.tprintf("/proc/%d/maps", pid))
    if err != nil {
        fmt.eprintln(color.red("Failed to open maps file with error: "), err)
    }
    defer os.close(maps_file)

    scanner: bufio.Scanner

    bufio.scanner_init(&scanner, os.stream_from_handle(maps_file))
    defer bufio.scanner_destroy(&scanner)

    for bufio.scanner_scan(&scanner) {
        line := bufio.scanner_text(&scanner)

        if len(strings.trim_space(line)) == 0 {
            continue
        }

        entry, ok := parse_map_line(line)
        if !ok {
            fmt.eprintln(color.red("Failed to parse map entry, skipping...\n"), "\bline: ", color.blue(line))
        } else {
            append(&maps, entry)
        }
    }

    return maps
}