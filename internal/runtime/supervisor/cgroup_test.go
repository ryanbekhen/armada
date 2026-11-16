package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadCgroup(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"cpu.stat":       "usage_usec 1500\nuser_usec 1000\nsystem_usec 500\n",
		"memory.stat":    "anon 4096\nfile 8192\ninactive_file 2048\nactive_file 6144\n",
		"memory.events":  "low 0\nhigh 0\nmax 3\noom 2\noom_kill 1\n",
		"memory.current": "12288\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m, err := readCgroup(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.GetCPU().GetUsageUsec() != 1500 || m.GetMemory().GetUsage() != 12288 || m.GetMemory().GetInactiveFile() != 2048 || m.GetMemoryEvents().GetOomKill() != 1 {
		t.Errorf("read %+v", m)
	}
	if _, err := readCgroup(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing cgroup read without an error")
	}
}
