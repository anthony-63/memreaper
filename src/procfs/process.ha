export type pid_t = u32;

export type process_t = struct {
    pid: pid_t,
    maps: []map_entry_t,
    status: status_t,
};

type invalid_path = !void;
type read_file_error = !(invalid_path | fs::error | io::error | utf8::invalid);

export fn open(pid: pid_t) (process_t | void) = {
    return process_t {
        pid = pid,
        maps = [],
        status = match(parse_status_file(pid)) {
            case let s: status_t => yield s;
            case => return void;
        },
    };
};