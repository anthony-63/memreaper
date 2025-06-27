use fmt;
use os;
use strconv;

use src::procfs;

fn usage() never = fmt::fatalf("usage: {} <pid>", os::args[0]);

export fn main() void = {
    if(len(os::args) != 2) usage();

    const pid = match (strconv::stou32(os::args[1])) {
        case let n: u32 => yield n;
        case => usage();
    };

    let proc = match(procfs::open(pid)) {
        case let p: procfs::process_t => yield p;
        case => fmt::fatalf("failed to open process at pid: {}", pid);
    };

    
};