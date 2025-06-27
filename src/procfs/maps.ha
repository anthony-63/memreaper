export type map_permissions = enum {
    READ    = 0b1,
    WRITE   = 0b10,
    EXECUTE = 0b100,
    SHARED  = 0b1000,
    PRIVATE = 0b10000,
};

export type map_entry_t = struct {
    start: u64,
    end: u64,

    perms: map_permissions,

    offs: u64,

    device: str,
    inode: u64,
    pathname: str,
};

type maps_erorr = !void;

fn read_maps(pid: pid_t) ([]map_entry_t | maps_erorr) = {
    let maps: []map_entry_t = [];
    
    

    return maps;
};