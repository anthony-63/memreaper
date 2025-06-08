package procfs

import "core:fmt"
import "core:os"
import "core:strings"
import "core:strconv"
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

    maps_bytes, success := os.read_entire_file_from_filename(fmt.tprintf("/proc/%d/maps", pid))
    if !success {
        fmt.eprintln(color.red("Failed to read processes map file with pid"), color.magenta(fmt.tprint(pid)))
    }
    
    maps_str, _ := strings.clone_from_bytes(maps_bytes)
    map_entries, _ := strings.split_lines(maps_str)

    for line in map_entries {
        if line == "" {
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