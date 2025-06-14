package procfs

import "core:fmt"
import "core:os"
import "core:strings"
import "core:strconv"
import "core:bufio"
import "core:slice"
import "../color"

Procfs_Status :: struct {
    name: string,
    cmdline: string,
    umask: uint,
    state: u8,
    
    tgid: int,
    ngid: int,
    pid: int,
    ppid: int,
    tracer_pid: int,
    
    uid_real: uint,
    uid_effective: uint,
    uid_saved: uint,
    uid_fs: uint,
    
    gid_real: uint,
    gid_effective: uint,
    gid_saved: uint,
    gid_fs: uint,
    
    fd_size: int,
    groups: []uint,
    
    vm_peak: u64,
    vm_size: u64,
    vm_lck: u64,
    vm_pin: u64,
    vm_hwm: u64,
    vm_rss: u64,
    rss_anon: u64,
    rss_file: u64,
    rss_shmem: u64,
    vm_data: u64,
    vm_stk: u64,
    vm_exe: u64,
    vm_lib: u64,
    vm_pte: u64,
    vm_swap: u64,
    hugetlb_pages: u64,
    
    threads: int,
    
    sig_q_queued: u64,
    sig_q_limit: u64,
    sig_pnd: u64,
    shd_pnd: u64,
    sig_blk: u64,
    sig_ign: u64,
    sig_cgt: u64,
    
    cap_inh: u64,
    cap_prm: u64,
    cap_eff: u64,
    cap_bnd: u64,
    cap_amb: u64,
    
    no_new_privs: int,
    seccomp: string,
    speculation_store_bypass: string,
    
    cpus_allowed_mask: u64,
    cpus_allowed_list: string,
    mems_allowed_mask: u64,
    mems_allowed_list: string,
    
    voluntary_ctxt_switches: u64,
    nonvoluntary_ctxt_switches: u64,
}

@(private="file")
parse_groups_line :: proc(line: string) -> []uint {
    groups: [dynamic]uint
    
    if tab_idx := strings.index(line, "\t"); tab_idx != -1 {
        groups_str := strings.trim_space(line[tab_idx+1:])
        if len(groups_str) == 0 do return slice.clone(groups[:])
        
        group_tokens := strings.fields(groups_str)
        defer delete(group_tokens)
        
        for token in group_tokens {
            append(&groups, strconv.parse_uint(token, 10) or_else 0)
        }
    }
    
    return slice.clone(groups[:])
}

@(private="file")
read_cmdline :: proc(pid: Pid) -> string {
    cmdline_path := fmt.tprintf("/proc/%d/cmdline", pid)
    
    cmdline_file, err := os.open(cmdline_path)
    if err != nil do return ""
    defer os.close(cmdline_file)
    
    data, ok := os.read_entire_file_from_handle(cmdline_file)
    if !ok do return ""
    defer delete(data)
    
    if len(data) == 0 do return ""
    
    cmdline_str := string(data)
    cmdline_clean, _ := strings.replace_all(cmdline_str, "\x00", " ")
    defer delete(cmdline_clean)
    
    cmdline_trimmed := strings.trim_space(cmdline_clean)
    
    if len(cmdline_trimmed) > 25 {
        if space_idx := strings.index(cmdline_trimmed[20:], " "); space_idx != -1 {
            return strings.clone(cmdline_trimmed[:20+space_idx])
        } else {
            return strings.clone(cmdline_trimmed[:25])
        }
    }

    return strings.clone(cmdline_str)
}

@(private="file")
parse_status_line :: proc(line: string, status: ^Procfs_Status) -> bool {
    if len(strings.trim_space(line)) == 0 do return true
    
    parts := strings.fields(line)
    if len(parts) < 2 do return true
    
    key := parts[0]
    
    switch key {
        case "Name:": status.name = strings.clone(parts[1])
        case "Umask:": status.umask = strconv.parse_uint(parts[1], 8) or_else 0
        case "State:": status.state = parts[1][0] if len(parts[1]) > 0 else 0
        case "Tgid:": status.tgid = strconv.parse_int(parts[1], 10) or_else 0
        case "Ngid:": status.ngid = strconv.parse_int(parts[1], 10) or_else 0
        case "Pid:": status.pid = strconv.parse_int(parts[1], 10) or_else 0
        case "PPid:": status.ppid = strconv.parse_int(parts[1], 10) or_else 0
        case "TracerPid:": status.tracer_pid = strconv.parse_int(parts[1], 10) or_else 0
        case "Uid:":
            if len(parts) >= 5 {
                status.uid_real = strconv.parse_uint(parts[1], 10) or_else 0
                status.uid_effective = strconv.parse_uint(parts[2], 10) or_else 0
                status.uid_saved = strconv.parse_uint(parts[3], 10) or_else 0
                status.uid_fs = strconv.parse_uint(parts[4], 10) or_else 0
            }
        case "Gid:":
            if len(parts) >= 5 {
                status.gid_real = strconv.parse_uint(parts[1], 10) or_else 0
                status.gid_effective = strconv.parse_uint(parts[2], 10) or_else 0
                status.gid_saved = strconv.parse_uint(parts[3], 10) or_else 0
                status.gid_fs = strconv.parse_uint(parts[4], 10) or_else 0
            }
        case "FDSize:": status.fd_size = strconv.parse_int(parts[1], 10) or_else 0
        case "Groups:": status.groups = parse_groups_line(line)
        case "VmPeak:": status.vm_peak = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmSize:": status.vm_size = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmLck:": status.vm_lck = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmPin:": status.vm_pin = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmHWM:": status.vm_hwm = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmRSS:": status.vm_rss = strconv.parse_u64(parts[1], 10) or_else 0
        case "RssAnon:": status.rss_anon = strconv.parse_u64(parts[1], 10) or_else 0
        case "RssFile:": status.rss_file = strconv.parse_u64(parts[1], 10) or_else 0
        case "RssShmem:": status.rss_shmem = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmData:": status.vm_data = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmStk:": status.vm_stk = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmExe:": status.vm_exe = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmLib:": status.vm_lib = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmPTE:": status.vm_pte = strconv.parse_u64(parts[1], 10) or_else 0
        case "VmSwap:": status.vm_swap = strconv.parse_u64(parts[1], 10) or_else 0
        case "HugetlbPages:": status.hugetlb_pages = strconv.parse_u64(parts[1], 10) or_else 0
        case "Threads:": status.threads = strconv.parse_int(parts[1], 10) or_else 0
        case "SigQ:":
            sig_parts := strings.split(parts[1], "/")
            defer delete(sig_parts)
            if len(sig_parts) == 2 {
                status.sig_q_queued = strconv.parse_u64(sig_parts[0], 10) or_else 0
                status.sig_q_limit = strconv.parse_u64(sig_parts[1], 10) or_else 0
            }
        case "SigPnd:": status.sig_pnd = strconv.parse_u64(parts[1], 16) or_else 0
        case "ShdPnd:": status.shd_pnd = strconv.parse_u64(parts[1], 16) or_else 0
        case "SigBlk:": status.sig_blk = strconv.parse_u64(parts[1], 16) or_else 0
        case "SigIgn:": status.sig_ign = strconv.parse_u64(parts[1], 16) or_else 0
        case "SigCgt:": status.sig_cgt = strconv.parse_u64(parts[1], 16) or_else 0
        case "CapInh:": status.cap_inh = strconv.parse_u64(parts[1], 16) or_else 0
        case "CapPrm:": status.cap_prm = strconv.parse_u64(parts[1], 16) or_else 0
        case "CapEff:": status.cap_eff = strconv.parse_u64(parts[1], 16) or_else 0
        case "CapBnd:": status.cap_bnd = strconv.parse_u64(parts[1], 16) or_else 0
        case "CapAmb:": status.cap_amb = strconv.parse_u64(parts[1], 16) or_else 0
        case "NoNewPrivs:": status.no_new_privs = strconv.parse_int(parts[1], 10) or_else 0
        case "Seccomp:": status.seccomp = strings.clone(parts[1])
        case "Speculation_Store_Bypass:": status.speculation_store_bypass = strings.clone(parts[1])
        case "Cpus_allowed:": status.cpus_allowed_mask = strconv.parse_u64(parts[1], 16) or_else 0
        case "Cpus_allowed_list:": status.cpus_allowed_list = strings.clone(parts[1])
        case "Mems_allowed:": status.mems_allowed_mask = strconv.parse_u64(parts[1], 16) or_else 0
        case "Mems_allowed_list:":status.mems_allowed_list = strings.clone(parts[1])
        case "voluntary_ctxt_switches:": status.voluntary_ctxt_switches = strconv.parse_u64(parts[1], 10) or_else 0
        case "nonvoluntary_ctxt_switches:": status.nonvoluntary_ctxt_switches = strconv.parse_u64(parts[1], 10) or_else 0
    }
    
    return true
}

read_procfs_status :: proc(pid: Pid) -> (Procfs_Status, bool) {
    status: Procfs_Status
    
    status_path := fmt.tprintf("/proc/%d/status", pid)
    defer delete(status_path)
    
    status_file, err := os.open(status_path)
    if err != nil {
        fmt.eprintln(color.red("Failed to open status file with error: "), err)
        return {}, false
    }
    defer os.close(status_file)
    
    scanner: bufio.Scanner
    bufio.scanner_init(&scanner, os.stream_from_handle(status_file))
    defer bufio.scanner_destroy(&scanner)
    
    for bufio.scanner_scan(&scanner) {
        line := bufio.scanner_text(&scanner)
        parse_status_line(line, &status)
    }
    
    status.cmdline = read_cmdline(pid)
    if len(status.cmdline) == 0 && len(status.name) > 0 {
        status.cmdline = fmt.aprintf("[%s]", status.name)
    }
    
    return status, true
}

delete_procfs_status :: proc(status: ^Procfs_Status) {
    if status == nil do return
    
    delete(status.name)
    delete(status.cmdline)
    delete(status.groups)
    delete(status.seccomp)
    delete(status.speculation_store_bypass)
    delete(status.cpus_allowed_list)
    delete(status.mems_allowed_list)
    
    status^ = {}
}