package main

import (
	"errors"
	"testing"
)

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil error", nil, 0},
		{"gate failure carries its own exit code", &gateFailure{ExitCode: 1}, 1},
		{"usage error is exit code 2", &usageError{"no command given"}, 2},
		{"any other error is exit code 1", errors.New("target unreachable"), 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exitCodeFor(c.err); got != c.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d", c.err, got, c.want)
			}
		})
	}
}

func TestDispatch_NoArgs(t *testing.T) {
	err := dispatch(nil)
	if err == nil {
		t.Fatal("dispatch with no args should return an error")
	}
	if _, ok := err.(*usageError); !ok {
		t.Errorf("error type = %T, want *usageError", err)
	}
	if exitCodeFor(err) != 2 {
		t.Errorf("exit code = %d, want 2", exitCodeFor(err))
	}
}

func TestDispatch_UnknownCommand(t *testing.T) {
	err := dispatch([]string{"definitely-not-a-real-command"})
	if err == nil {
		t.Fatal("dispatch with an unknown command should return an error")
	}
	if _, ok := err.(*usageError); !ok {
		t.Errorf("error type = %T, want *usageError", err)
	}
}

func TestDispatch_Help(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}} {
		t.Run(args[0], func(t *testing.T) {
			if err := dispatch(args); err != nil {
				t.Errorf("dispatch(%v) returned an error: %v", args, err)
			}
		})
	}
}

func TestDispatch_Version(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"-v"}, {"--version"}} {
		t.Run(args[0], func(t *testing.T) {
			if err := dispatch(args); err != nil {
				t.Errorf("dispatch(%v) returned an error: %v", args, err)
			}
		})
	}
}

// dispatch just routes to the cmdX functions - errors from a genuinely
// broken invocation (missing required config) should flow straight through
// as a plain error, not get reinterpreted as a usage or gate error.
func TestDispatch_RoutesToSubcommandsAndPropagatesErrors(t *testing.T) {
	err := dispatch([]string{"validate"}) // no --environment given, and validate requires it
	if err == nil {
		t.Fatal("dispatch([\"validate\"]) with no --environment should fail")
	}
	if _, ok := err.(*usageError); ok {
		t.Error("a missing required flag is an operational error, not a CLI usage error")
	}
	if _, ok := err.(*gateFailure); ok {
		t.Error("a missing required flag should not be reported as a gate failure")
	}
}
