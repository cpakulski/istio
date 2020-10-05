package vm

import (
	"fmt"
	"strconv"

	"golang.org/x/crypto/ssh"
	_ "golang.org/x/crypto/ssh/knownhosts"
	_ "golang.org/x/crypto/ssh/terminal"
)

//VMsshConfig contains params required for successful SSH connection
type VMsshConfig struct {
	Address         string
	SshUser         string
	SshAuthMethod   ssh.AuthMethod
	HostKeyCallback ssh.HostKeyCallback
	SshPort         int
}

// VM encapsulates SSH connection the VM machine
type VM struct {
	SshConfig *VMsshConfig
	client    *ssh.Client
}

func (vm *VM) Connect() error {
	sshConfig := &ssh.ClientConfig{
		User:            vm.SshConfig.SshUser,
		Auth:            []ssh.AuthMethod{vm.SshConfig.SshAuthMethod},
		HostKeyCallback: vm.SshConfig.HostKeyCallback,
	}
	var err error
	vm.client, err = ssh.Dial("tcp", vm.SshConfig.Address+":"+strconv.Itoa(vm.SshConfig.SshPort), sshConfig)
	if err != nil {
		return err
	}
	return nil
}

// ExecuteCommand runs a shell command after SSH connection has been established.
func (vm *VM) ExecuteOneSSHCommand(command string) error {
	session, err := vm.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	return session.Run(command)
}

type SshAction struct {
	Title   string
	Command string
}

func (vm *VM) ExecuteManySSHCommands(actions *[]SshAction) (int, error) {
	for i, action := range *actions {
		if len(action.Title) != 0 {
			fmt.Println(action.Title)
		}
		err := vm.ExecuteOneSSHCommand(action.Command)
		if err != nil {
			return i, err
		}
	}
	return 0, nil
}
