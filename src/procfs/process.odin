package procfs

Pid :: uint

Process :: struct {
   pid: Pid,
   maps: []Procfs_Map_Entry,
   status: Procfs_Status
}

open_process :: proc(pid: Pid) -> Process {
   return Process {
      pid = pid,
      maps = read_procfs_maps(pid)[:],
      status = read_procfs_status(pid) or_else Procfs_Status{},
   }
}

refresh_process :: proc(process: ^Process) {
   process.maps = read_procfs_maps(process.pid)[:]
   process.status = read_procfs_status(process.pid) or_else Procfs_Status{}
}

delete_process :: proc(process: ^Process) {
   delete_procfs_status(&process.status)
   delete_procfs_maps(process.maps)
}