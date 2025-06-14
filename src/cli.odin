package main

import "core:fmt"
import "core:os"
import "core:strings"

import "color"

Command :: struct($T: typeid) {
    cmd: string,
    desc: string,
    callback: proc(data: ^T, args: []string)
}

cmd :: proc(cmd: string, desc: string, callback: proc(data: ^$T, args: []string)) -> Command(T) {
    return Command(T) {
        cmd = cmd,
        desc = desc,
        callback = callback
    }
}

@(private="file")
parse_args :: proc(args: []string) -> []string {
    if len(args) < 1 {
        return {}
    }
    
    args_res: [dynamic]string
    defer delete(args_res)
    
    i := 0
    for i < len(args) {
        arg := args[i]
        
        if strings.starts_with(arg, "\"") {
            quoted_parts: [dynamic]string
            defer delete(quoted_parts)
            
            first_part := arg[1:] // Remove leading quote
            append(&quoted_parts, first_part)
            
            if strings.ends_with(arg, "\"") && len(arg) > 1 {
                content := strings.join(quoted_parts[:], " ")
                if len(content) > 0 && content[len(content)-1] == '"' {
                    content = content[:len(content)-1]
                }
                append(&args_res, content)
                i += 1
                continue
            }
            
            i += 1
            found_closing := false
            
            for i < len(args) {
                next_arg := args[i]
                append(&quoted_parts, next_arg)
                
                if strings.ends_with(next_arg, "\"") {
                    found_closing = true
                    break
                }
                i += 1
            }
            
            content := strings.join(quoted_parts[:], " ")
            if found_closing && len(content) > 0 && content[len(content)-1] == '"' {
                content = content[:len(content)-1]
            }
            
            append(&args_res, content)
            i += 1
        } else {
            append(&args_res, arg)
            i += 1
        }
    }
    
    result := make([]string, len(args_res))
    copy(result, args_res[:])
    return result
}

run_cli :: proc(commands: []Command($T), data: ^T) {
    for cmd in commands {
        if cmd.cmd == "init" {
            cmd.callback(data, {})
        }
    }
    
    for true {
        buf := [2048]u8{}
        
        fmt.printf("%s> ", color.bright_cyan("memreaper"))
        read_size, err := os.read(os.stdin, buf[:])
        if err != nil {
            fmt.eprintln(color.red("failed to read input"))
            continue
        }

        cmd_str := strings.trim(string(buf[:read_size]), "\n ")
        cmds, _ := strings.split(cmd_str, " ")
        if len(cmds) < 1 {
            continue
        }
        cmd := cmds[0]
        args_strs: []string
        if len(cmds) > 1 {
            args_strs = cmds[1:]
        }

        args := parse_args(args_strs)
        defer delete(args)

        for cmd_ in commands {
            if cmd_.cmd == cmd {
                cmd_.callback(data, args)
            }
        }
    }

}