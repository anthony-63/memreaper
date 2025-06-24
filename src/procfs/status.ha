use io;
use os;
use fmt;
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
type cmdline_error = !void;
type pair_error = !void;

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

fn parse_status_cmdline(pid: pid_t) (str | cmdline_error) = {
    let cmdline_path = match(strings::concat("/proc/", strconv::utos(pid), "/cmdline")) {
        case let s: str => yield s;
        case => return cmdline_error;
    };

    const cmdline = match(os::open(cmdline_path)) {
        case let file: io::file => yield file;
        case => {
            const _p = fmt::println("Failed to open cmdline file");
            return cmdline_error;
        };
    };
    const cmdline = match(io::drain(cmdline)) {
        case let bytes: []u8 => yield bytes;
        case => {
            const _p = fmt::println("Failed to read cmdline file");
            return cmdline_error;
        };
    };
    const cmdline = match(strings::fromutf8(cmdline)) {
        case let string: str => yield string;
        case => {
            const _p = fmt::println("Failed to parse cmdline file");
            return cmdline_error;
        };
    };

    return cmdline;
};

fn parse_status_line(line: str, status: *status_t) (void | pair_error) = {
	if (strings::trim(line) == "") return;

	let parts = match(strings::split(line, ":")) {
		case let val: []str => yield val;
		case => return pair_error;
	};
	if (len(parts) < 2) return;

	let key = parts[0];
	let val = strings::trim(parts[1]);

	const size_str = match(strings::split(val, " ")) {
		case let val: []str => yield val;
		case => return pair_error;
	};
    const size_str = if(len(size_str) > 0) {
        yield size_str[0];
    } else {
        yield "";
    };

	switch (key) {
        case "Name" => status.name = strings::dup(val) as str;
        case "Umask" => status.umask = strconv::stou(val, 8) as uint;
        case "State" => status.state = if (len(val) > 0) strings::toutf8(val)[0] else 0;
        case "Tgid" =>
            status.tgid = match (strconv::stoi(val)) {
                case let i: int => yield i;
                case => return pair_error;
            };
        case "Ngid" =>
            status.ngid = match (strconv::stoi(val)) {
                case let i: int => yield i;
                case => return pair_error;
            };
        case "Pid" =>
            status.pid = match (strconv::stoi(val)) {
                case let i: int => yield i;
                case => return pair_error;
            };
        case "PPid" =>
            status.ppid = match (strconv::stoi(val)) {
                case let i: int => yield i;
                case => return pair_error;
            };
        case "TracerPid" =>
            status.tracer_pid = match (strconv::stoi(val)) {
                case let i: int => yield i;
                case => return pair_error;
            };
        case "Uid" =>
            let uids = match(strings::split(val, " ")) {
                case let s: []str => yield s;
                case => return pair_error;
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
                case => return pair_error;
            };
            if (len(gids) >= 4) {
                status.gid_real = strconv::stou(gids[0]) as uint;
                status.gid_effective = strconv::stou(gids[1]) as uint;
                status.gid_saved = strconv::stou(gids[2]) as uint;
                status.gid_fs = strconv::stou(gids[3]) as uint;
            };
        case "FDSize" =>
            status.fd_size = match(strconv::stoi(val)) {
                case let i: int => yield i;
                case => return pair_error;
            };
        case "Groups" =>
            status.groups = match(parse_status_group_line(val)) {
                case let groups: []uint => yield groups;
                case => {
                    const _p = fmt::println("Malformed status file(groups)");
                    return pair_error;
                };
            };
        case "VmPeak" =>
            status.vm_peak = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmSize" =>
            status.vm_size = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmLck" =>
            status.vm_lck = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmPin" =>
            status.vm_pin = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmHWM" =>
            status.vm_hwm = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmRSS" =>
            status.vm_rss = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "RssAnon" =>
            status.rss_anon = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "RssFile" =>
            status.rss_file = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "RssShmem" =>
            status.rss_shmem = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmData" =>
            status.vm_data = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmStk" =>
            status.vm_stk = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmExe" =>
            status.vm_exe = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmLib" =>
            status.vm_lib = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmPTE" =>
            status.vm_pte = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "VmSwap" =>
            status.vm_swap = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "HugetlbPages" =>
            status.hugetlb_pages = match (strconv::stoz(size_str)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "Threads" =>
            status.threads = match (strconv::stoi(val)) {
                case let i: int => yield i;
                case => return pair_error;
            };
        case "SigQ" =>
            let sig_parts = match(strings::split(val, "/")) {
                case let s: []str => yield s;
                case => return pair_error;
            };
            if (len(sig_parts) == 2) {
                status.sig_q_queued = match (strconv::stoz(sig_parts[0])) {
                    case let i: size => yield i;
                    case => return pair_error;
                };
                status.sig_q_limit = match (strconv::stoz(sig_parts[1])) {
                    case let i: size => yield i;
                    case => return pair_error;
                };
            };
        case "SigPnd" =>
            status.sig_pnd = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "ShdPnd" =>
            status.shd_pnd = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "SigBlk" =>
            status.sig_blk = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "SigIgn" =>
            status.sig_ign = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "SigCgt" =>
            status.sig_cgt = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "CapInh" =>
            status.cap_inh = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "CapPrm" =>
            status.cap_prm = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "CapEff" =>
            status.cap_eff = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "CapBnd" =>
            status.cap_bnd = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "CapAmb" =>
            status.cap_amb = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "NoNewPrivs" =>
            status.no_new_privs = match (strconv::stoi(val)) {
                case let i: int => yield i;
                case => return pair_error;
            };
        case "Seccomp" => status.seccomp = strings::dup(val) as str;
        case "Speculation_Store_Bypass" => status.speculation_store_bypass = strings::dup(val) as str;
        case "Cpus_allowed" =>
            status.cpus_allowed_mask = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "Cpus_allowed_list" => status.cpus_allowed_list = strings::dup(val) as str;
        case "Mems_allowed_list" =>
            status.mems_allowed_list = strings::dup(val) as str;
        case "voluntary_ctxt_switches" =>
            status.voluntary_ctxt_switches = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case "nonvoluntary_ctxt_switches" =>
            status.nonvoluntary_ctxt_switches = match (strconv::stoz(val, 16)) {
                case let i: size => yield i;
                case => return pair_error;
            };
        case => return;
	};
};

fn parse_status_file(pid: pid_t) (status_t | void) = {
    let status = status_t {...};

    let status_path = match(strings::concat("/proc/", strconv::utos(pid), "/status")) {
        case let s: str => yield s;
        case => return void;
    };

    const status_src = match(os::open(status_path)) {
        case let file: io::file => yield file;
        case => {
            const _p = fmt::println("Failed to open status file");
            return void;
        };
    };
    const status_src = match(io::drain(status_src)) {
        case let bytes: []u8 => yield bytes;
        case => {
            const _p = fmt::println("Failed to read status file");
            return void;
        };
    };
    const status_src = match(strings::fromutf8(status_src)) {
        case let string: str => yield string;
        case => {
            const _p = fmt::println("Failed to parse status file");
            return void;
        };
    };
    const status_src = match(strings::split(status_src, "\n")) {
        case let split: []str => yield split;
        case => {
            const _p = fmt::println("Failed to split status file");
            return void;
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