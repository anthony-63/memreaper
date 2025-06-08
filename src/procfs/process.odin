package procfs

Pid :: uint

Process :: struct {
   pid: Pid,
   maps: []Map_Entry,
}

open_process :: proc(pid: Pid) -> Process {
   return Process{
      pid = pid,
      maps = read_procfs_maps(pid)[:]
   }
}