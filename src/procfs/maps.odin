package procfs

import "core:fmt"
import "core:os"
import "core:strings"
import "core:strconv"
import "core:bufio"
import color "../../external/odin-color"

Procfs_Map_Permission :: enum {
    Read,
    Write,
    Execute,
    Shared,
    Private,
}

Procfs_Map_Permission_Set :: bit_set[Procfs_Map_Permission]

Procfs_Map_Entry :: struct {
    start: u64,
    end: u64,

    permissions: Procfs_Map_Permission_Set,

    offset: u64,

    device: string,
    inode: u64,

    pathname: string,
}

@(private="file")
parse_permissions :: proc(perms_str: string) -> (Procfs_Map_Permission_Set, bool) {
    perms: Procfs_Map_Permission_Set
    
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
parse_map_line :: proc(line: string) -> (entry: Procfs_Map_Entry, ok: bool) {
    parts := strings.fields(line)
    if len(parts) < 5 do return {}, false
    
    addr_parts := strings.split(parts[0], "-")
    if len(addr_parts) != 2 do return {}, false
    defer delete(addr_parts)
    
    entry.start = strconv.parse_u64(addr_parts[0], 16) or_return
    entry.end = strconv.parse_u64(addr_parts[1], 16) or_return
    entry.permissions = parse_permissions(strings.clone(parts[1])) or_return
    entry.offset = strconv.parse_u64(parts[2], 16) or_return
    entry.device = strings.clone(parts[3])

    if len(parts) > 5 {
        pathname_parts := parts[5:]
        entry.pathname = strings.clone(strings.join(pathname_parts, " "))
    }
    
    return entry, true
}

read_procfs_maps :: proc(pid: Pid) -> [dynamic]Procfs_Map_Entry {
    maps: [dynamic]Procfs_Map_Entry

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

delete_procfs_maps :: proc(maps: []Procfs_Map_Entry) {
    for mmap in maps {
        delete(mmap.device)
        delete(mmap.pathname)
    }
}