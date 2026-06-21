package main

import "fmt"

type commandEntry struct {
	name    string
	usage   string
	help    string
	handler func(sh *Shell, args []string) error
}

var commands []commandEntry
var commandMap map[string]*commandEntry

func init() {
	commands = []commandEntry{
		{"connect", "connect <alias> <host:port>", "Connect to a peer and perform handshake", cmdConnect},
		{"disconnect", "disconnect <alias>", "Disconnect from a peer", cmdDisconnect},
		{"ls", "ls [path]", "List children at path (or current directory)", cmdLs},
		{"cd", "cd <path>", "Change working directory", cmdCd},
		{"pwd", "pwd", "Print working directory", cmdPwd},
		{"cat", "cat <path> [-diag]", "Display entity at path", cmdCat},
		{"tree", "tree [path] [-depth N] [-v]", "Recursive tree listing (-v shows entity details)", cmdTree},
		{"exec", "exec <handler> <op> [resource]", "Execute operation on current peer", cmdExec},
		{"info", "info [alias]", "Show connection details", cmdInfo},
		{"help", "help [command]", "Show help", cmdHelp},
	}
	commandMap = make(map[string]*commandEntry, len(commands))
	for i := range commands {
		commandMap[commands[i].name] = &commands[i]
	}
}

func (sh *Shell) dispatch(name string, args []string) error {
	entry, ok := commandMap[name]
	if !ok {
		return fmt.Errorf("unknown command: %s (type 'help' for commands)", name)
	}
	return entry.handler(sh, args)
}
