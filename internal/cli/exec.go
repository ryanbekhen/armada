package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	armadav1 "github.com/ryanbekhen/armada/api/armada/v1"
	"github.com/ryanbekhen/armada/internal/runtime"
)

// defaultShell is what exec runs without a command.
const defaultShell = "/bin/sh"

// exitCodeError ends the CLI with a command's exit code and no message.
type exitCodeError int

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func newAppExecCommand(g *globals) *cobra.Command {
	var (
		replica    string
		ctr        string
		stdin, tty bool
	)
	cmd := &cobra.Command{
		Use:   "exec APP [--replica R] [--container C] [-- COMMAND...]",
		Short: "Run a command, or a shell, in one of an app's replicas",
		Long: `Run a command in one of an app's replicas and exit with its exit code.
Without a command it opens a shell (/bin/sh).

Runs in a ready replica of the serving revision unless --replica picks one;
` + "`armada replica list APP`" + ` shows the replicas and their containers. --container
runs it in one of the replica's sidecars instead of the app's own container.
When standard input is a terminal the command gets it and a terminal of its
own; -i and -t (or -i=false, -t=false) say otherwise. The command runs with
the container's own user and security settings.

Exec is for diagnosis: changes made inside a container are lost when its
replica is replaced. Each session is recorded in the audit log with the
command's name, not its arguments.`,
		Example: `  armada app exec api                        # a shell in one of api's replicas
  armada app exec api -- env                 # run one command
  armada app exec api --container log-ship   # a shell in a sidecar
  armada app exec api --replica k3p9x -- ps  # in one replica (armada replica list api)`,
		Args: func(cmd *cobra.Command, args []string) error {
			switch dash := cmd.ArgsLenAtDash(); {
			case len(args) == 0:
				return argError(cmd, args)
			case dash == -1 && len(args) > 1:
				// Never repeat the command: its arguments may hold a secret.
				return errors.New("put -- before the command: armada app exec APP -- COMMAND")
			case dash > 1:
				return errors.New("give one app before --")
			case dash == 0:
				return errors.New("missing APP before --")
			}
			if len(args) == 1 {
				return nil
			}
			return runtime.CheckExecCommand(args[1:])
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := g.qualify(args); err != nil {
				return err
			}
			command := args[1:]
			if len(command) == 0 {
				command = []string{defaultShell}
			}
			in := cmd.InOrStdin()
			inFile, inOK := in.(*os.File)
			outFile, outOK := cmd.OutOrStdout().(*os.File)
			inTerm := inOK && term.IsTerminal(int(inFile.Fd()))
			outTerm := outOK && term.IsTerminal(int(outFile.Fd()))
			// A person at a terminal gets an interactive session unless a
			// flag says otherwise (ADR 0052).
			if !cmd.Flags().Changed("stdin") {
				stdin = inTerm
			}
			if !cmd.Flags().Changed("tty") {
				tty = inTerm && outTerm
			}
			var fd int
			if tty {
				if !inTerm || !outTerm {
					return errors.New("-t needs a terminal on standard input and output; leave it out to run without one")
				}
				fd = int(inFile.Fd())
			}
			client, conn, err := dialAdmin(g)
			if err != nil {
				return err
			}
			defer conn.Close()
			stream, err := client.Exec(cmd.Context())
			if err != nil {
				return RPCError(err)
			}
			var mu sync.Mutex // serializes sends
			send := func(m *armadav1.ExecClientMessage) error {
				mu.Lock()
				defer mu.Unlock()
				return stream.Send(m)
			}
			input := func(in *armadav1.ExecInput) error {
				return send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Input{Input: in}})
			}
			start := &armadav1.ExecStart{App: args[0], Replica: replica, Cmd: command, Tty: tty, Stdin: stdin, Container: ctr}
			if tty {
				if cols, rows, err := term.GetSize(fd); err == nil {
					start.Size = &armadav1.TermSize{Rows: uint32(max(rows, 0)), Cols: uint32(max(cols, 0))} //nolint:gosec // non-negative
				}
			}
			if err := send(&armadav1.ExecClientMessage{Msg: &armadav1.ExecClientMessage_Start{Start: start}}); err != nil {
				return RPCError(err)
			}
			// The first message names the replica, or the error that kept
			// the command from starting.
			first, err := stream.Recv()
			if err != nil {
				return RPCError(err)
			}
			if first.GetReplica() == "" {
				return errors.New("server did not start the command")
			}

			if tty {
				old, err := term.MakeRaw(fd)
				if err != nil {
					return fmt.Errorf("terminal raw mode: %w", err)
				}
				defer func() { _ = term.Restore(fd, old) }()
				winch := make(chan os.Signal, 1)
				signal.Notify(winch, syscall.SIGWINCH)
				defer signal.Stop(winch)
				go func() {
					for range winch {
						if cols, rows, err := term.GetSize(fd); err == nil {
							_ = input(&armadav1.ExecInput{Input: &armadav1.ExecInput_Resize{Resize: &armadav1.TermSize{Rows: uint32(max(rows, 0)), Cols: uint32(max(cols, 0))}}}) //nolint:gosec // non-negative
						}
					}
				}()
			}
			if stdin {
				go func() {
					buf := make([]byte, runtime.MaxExecChunk)
					for {
						n, err := in.Read(buf)
						if n > 0 {
							if input(&armadav1.ExecInput{Input: &armadav1.ExecInput_Stdin{Stdin: append([]byte(nil), buf[:n]...)}}) != nil {
								return
							}
						}
						if err != nil {
							if errors.Is(err, io.EOF) {
								_ = input(&armadav1.ExecInput{Input: &armadav1.ExecInput_CloseStdin{CloseStdin: true}})
							}
							return
						}
					}
				}()
			}
			for {
				m, err := stream.Recv()
				if err != nil {
					if errors.Is(err, io.EOF) {
						return errors.New("server ended the session without an exit code")
					}
					return RPCError(err)
				}
				switch o := m.GetMsg().(type) {
				case *armadav1.ExecServerMessage_Stdout:
					_, _ = cmd.OutOrStdout().Write(o.Stdout)
				case *armadav1.ExecServerMessage_Stderr:
					_, _ = cmd.ErrOrStderr().Write(o.Stderr)
				case *armadav1.ExecServerMessage_ExitCode:
					if o.ExitCode != 0 {
						return exitCodeError(o.ExitCode)
					}
					return nil
				}
			}
		},
	}
	f := cmd.Flags()
	f.StringVar(&replica, "replica", "", "run in this replica: its short name from armada replica list, or its ID")
	f.StringVar(&ctr, "container", "", "run in this sidecar instead of the app's own container")
	f.BoolVarP(&stdin, "stdin", "i", false, "pass standard input to the command (default: when it is a terminal)")
	f.BoolVarP(&tty, "tty", "t", false, "allocate a terminal (default: when standard input and output are terminals)")
	return cmd
}
