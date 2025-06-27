use io;
use os;
use fs;
use fmt;
use encoding::utf8;
use strings;
use strconv;

export type status_t = struct {
    name: str,
    cmdline: str,
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
    
    vm_peak: size,
    vm_size: size,
    vm_lck: size,
    vm_pin: size,
    vm_hwm: size,
    vm_rss: size,
    rss_anon: size,
    rss_file: size,
    rss_shmem: size,
    vm_data: size,
    vm_stk: size,
    vm_exe: size,
    vm_lib: size,
    vm_pte: size,
    vm_swap: size,
    hugetlb_pages: size,
    
    threads: int,
    
    sig_q_queued: size,
    sig_q_limit: size,
    sig_pnd: size,
    shd_pnd: size,
    sig_blk: size,
    sig_ign: size,
    sig_cgt: size,
    
    cap_inh: size,
    cap_prm: size,
    cap_eff: size,
    cap_bnd: size,
    cap_amb: size,
    
    no_new_privs: int,
    seccomp: str,
    speculation_store_bypass: str,
    
    cpus_allowed_mask: size,
    cpus_allowed_list: str,
    mems_allowed_mask: size,
    mems_allowed_list: str,
    
    voluntary_ctxt_switches: size,
    nonvoluntary_ctxt_switches: size,
};

type group_error = !void;

type malformed_status = !void;

type malformed_pair = !void;
type pair_error = !(malformed_pair | strconv::invalid | strconv::overflow);

fn parse_status_group_line(line: str) ([]uint | group_error) = {
    let groups: []uint = [];

    const groups_str = strings::cut(line, "\t").1;

    if(len(groups_str) == 0) return groups;

    const group_tokens = match(strings::split(groups_str, " ")) {
        case let toks: []str => yield toks;
        case => return groups;
    };

    for(let tok .. group_tokens) {
        const num = match(strconv::stou(tok)) {
            case let v: uint => yield v;
            case => return group_error;
        };
        let ignore = append(groups, num);
    };

    return groups;
};

fn parse_status_cmdline(pid: pid_t) (str | read_file_error) = {
    let cmdline_path = match(strings::concat("/proc/", strconv::utos(pid), "/cmdline")) {
        case let s: str => yield s;
        case => return invalid_path;
    };

    const cmdline = os::open(cmdline_path)?;
    const cmdline = io::drain(cmdline)?;
    const cmdline = strings::fromutf8(cmdline)?;

    return cmdline;
};

fn parse_status_line(line: str, status: *status_t) (void | pair_error) = {
	if (strings::trim(line) == "") return;

	let parts = match(strings::split(line, ":")) {
		case let val: []str => yield val;
		case => return malformed_pair;
	};
	if (len(parts) < 2) return;

	let key = parts[0];
	let val = strings::trim(parts[1]);

	const size_str = match(strings::split(val, " ")) {
		case let val: []str => yield val;
		case => return malformed_pair;
	};
    const size_str = if(len(size_str) > 0) {
        yield size_str[0];
    } else {
        yield "";
    };

	switch (key) {
        case "Name" => status.name = val;
        case "Umask" => status.umask = strconv::stou(val, 8) as uint;
        case "State" => status.state = if (len(val) > 0) strings::toutf8(val)[0] else 0;
        case "Tgid" => status.tgid = strconv::stoi(val)?;
        case "Ngid" => status.ngid = strconv::stoi(val)?;
        case "Pid" => status.pid = strconv::stoi(val)?;
        case "PPid" => status.ppid = strconv::stoi(val)?;
        case "TracerPid" => status.tracer_pid = strconv::stoi(val)?;
        case "Uid" =>
            let uids = match(strings::split(val, " ")) {
                case let s: []str => yield s;
                case => return malformed_pair;
            };
            if (len(uids) >= 4) {
                status.uid_real = strconv::stou(uids[0]) as uint;
                status.uid_effective = strconv::stou(uids[1]) as uint;
                status.uid_saved = strconv::stou(uids[2]) as uint;
                status.uid_fs = strconv::stou(uids[3]) as uint;
            };
        case "Gid" =>
            let gids = match(strings::split(val, " ")) {
                case let s: []str => yield s;
                case => return malformed_pair;
            };
            if (len(gids) >= 4) {
                status.gid_real = strconv::stou(gids[0]) as uint;
                status.gid_effective = strconv::stou(gids[1]) as uint;
                status.gid_saved = strconv::stou(gids[2]) as uint;
                status.gid_fs = strconv::stou(gids[3]) as uint;
            };
        case "FDSize" => status.fd_size = strconv::stoi(val)?;
        case "Groups" =>
            status.groups = match(parse_status_group_line(val)) {
                case let groups: []uint => yield groups;
                case => {
                    const _p = fmt::println("Malformed status file(groups)");
                    return malformed_pair;
                };
            };
        case "VmPeak" => status.vm_peak = strconv::stoz(size_str)?;
        case "VmSize" => status.vm_size = strconv::stoz(size_str)?;
        case "VmLck" => status.vm_lck = strconv::stoz(size_str)?;
        case "VmPin" => status.vm_pin = strconv::stoz(size_str)?;
        case "VmHWM" => status.vm_hwm = strconv::stoz(size_str)?;
        case "VmRSS" => status.vm_rss = strconv::stoz(size_str)?;
        case "RssAnon" => status.rss_anon = strconv::stoz(size_str)?;
        case "RssFile" => status.rss_file = strconv::stoz(size_str)?;
        case "RssShmem" => status.rss_shmem = strconv::stoz(size_str)?;
        case "VmData" => status.vm_data = strconv::stoz(size_str)?;
        case "VmStk" => status.vm_stk = strconv::stoz(size_str)?;
        case "VmExe" => status.vm_exe = strconv::stoz(size_str)?;
        case "VmLib" => status.vm_lib = strconv::stoz(size_str)?;
        case "VmPTE" => status.vm_pte = strconv::stoz(size_str)?;
        case "VmSwap" => status.vm_swap = strconv::stoz(size_str)?;
        case "HugetlbPages" => status.hugetlb_pages = strconv::stoz(size_str)?;
        case "Threads" => status.threads = strconv::stoi(val)?;
        case "SigQ" =>
            let sig_parts = match(strings::split(val, "/")) {
                case let s: []str => yield s;
                case => return malformed_pair;
            };
            if (len(sig_parts) == 2) {
                status.sig_q_queued = strconv::stoz(sig_parts[0])?;
                status.sig_q_limit = strconv::stoz(sig_parts[1])?;
            };
        case "SigPnd" => status.sig_pnd = strconv::stoz(val, 16)?;
        case "ShdPnd" => status.shd_pnd = strconv::stoz(val, 16)?;
        case "SigBlk" => status.sig_blk = strconv::stoz(val, 16)?;
        case "SigIgn" => status.sig_ign = strconv::stoz(val, 16)?;
        case "SigCgt" => status.sig_cgt = strconv::stoz(val, 16)?;
        case "CapInh" => status.cap_inh = strconv::stoz(val, 16)?;
        case "CapPrm" => status.cap_prm = strconv::stoz(val, 16)?;
        case "CapEff" => status.cap_eff = strconv::stoz(val, 16)?;
        case "CapBnd" => status.cap_bnd = strconv::stoz(val, 16)?;
        case "CapAmb" => status.cap_amb = strconv::stoz(val, 16)?;
        case "NoNewPrivs" => status.no_new_privs = strconv::stoi(val)?;
        case "Seccomp" => status.seccomp = val;
        case "Speculation_Store_Bypass" => status.speculation_store_bypass = val;
        case "Cpus_allowed" => strconv::stoz(val, 16)?;
        case "Cpus_allowed_list" => status.cpus_allowed_list = val;
        case "Mems_allowed_list" => status.mems_allowed_list = val;
        case "voluntary_ctxt_switches" => status.voluntary_ctxt_switches = strconv::stoz(val, 16)?;
        case "nonvoluntary_ctxt_switches" => status.nonvoluntary_ctxt_switches = strconv::stoz(val, 16)?;
        case => return;
	};
};

fn parse_status_file(pid: pid_t) (status_t | read_file_error | malformed_status) = {
    let status = status_t {...};

    let status_path = match(strings::concat("/proc/", strconv::utos(pid), "/status")) {
        case let s: str => yield s;
        case => return invalid_path;
    };

    const status_src = os::open(status_path)?;
    const status_src = io::drain(status_src)?;
    const status_src = strings::fromutf8(status_src)?;

    const status_src = match(strings::split(status_src, "\n")) {
        case let split: []str => yield split;
        case => {
            const _p = fmt::println("Failed to split status file");
            return malformed_status;
        };
    };

    for(let pair .. status_src) {
        match(parse_status_line(pair, &status)) {
            case pair_error => const _p = fmt::println("Failed to parse line: ", pair);
            case => continue;
        };
    };

    status.cmdline = match(parse_status_cmdline(pid)) {
        case let cmdline: str => yield cmdline;
        case => {
            const _p = fmt::println("Failed to parse cmdline");
            return status;
        };
    };

    return status;
};
