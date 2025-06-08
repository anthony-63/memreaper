package main

import "core:fmt"
import procfs "procfs"

main :: proc() {
    process := procfs.open_process(1)

    for mmap in process.maps {
        fmt.println(mmap)
    }
}