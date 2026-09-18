// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package capture

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestClassificationCache(t *testing.T) {
	st, err := os.Stat("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	id := executableIdentity(st.Sys().(*syscall.Stat_t))
	cache := make(map[executableID]bool)
	proc := t.TempDir()
	if got := classify(proc, 1, "/bin/sh", id, cache); got != tlsNone {
		t.Fatalf("shell classified as %v", got)
	}
	if goTLS, ok := cache[id]; !ok || goTLS {
		t.Fatal("negative Go TLS result was not cached")
	}
	// A cached positive result must not require opening the executable again.
	cache[id] = true
	if got := classify(proc, 1, "/missing", id, cache); got != tlsGo {
		t.Fatalf("cache hit: %v", got)
	}
	changed := id
	changed.changed++
	if got := classify(proc, 1, "/missing", changed, cache); got != tlsNone {
		t.Fatalf("reused stale identity: %v", got)
	}
	if _, ok := cache[changed]; ok {
		t.Fatal("transient open failure must be retried")
	}
	if got := classify(proc, 1, "/bin/sh", changed, cache); got != tlsNone {
		t.Fatalf("retry: %v", got)
	}
	if _, ok := cache[changed]; !ok {
		t.Fatal("successful retry was not cached")
	}
}

func TestExecutableIdentity(t *testing.T) {
	base := syscall.Stat_t{Dev: 1, Ino: 2, Size: 100, Mtim: syscall.Timespec{Sec: 1}, Ctim: syscall.Timespec{Sec: 2}}
	for _, change := range []func(*syscall.Stat_t){
		func(s *syscall.Stat_t) { s.Dev++ }, func(s *syscall.Stat_t) { s.Ino++ },
		func(s *syscall.Stat_t) { s.Size++ }, func(s *syscall.Stat_t) { s.Mtim.Nsec++ },
		func(s *syscall.Stat_t) { s.Ctim.Nsec++ },
	} {
		next := base
		change(&next)
		if executableIdentity(&base) == executableIdentity(&next) {
			t.Fatal("executable identity did not change")
		}
	}
}

func TestScanForgetsExitedExecutables(t *testing.T) {
	proc := t.TempDir()
	for _, pid := range []string{"1", "2"} {
		if err := os.Mkdir(filepath.Join(proc, pid), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/bin/sh", filepath.Join(proc, pid, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	c := &Capture{procFS: proc, goTLS: make(map[executableID]bool)}
	c.Scan()
	if len(c.goTLS) != 1 {
		t.Fatalf("same executable cached %d times", len(c.goTLS))
	}
	if err := os.RemoveAll(filepath.Join(proc, "1")); err != nil {
		t.Fatal(err)
	}
	c.Scan()
	if len(c.goTLS) != 1 {
		t.Fatal("forgot executable still used by another process")
	}
	if err := os.RemoveAll(filepath.Join(proc, "2")); err != nil {
		t.Fatal(err)
	}
	c.Scan()
	if len(c.goTLS) != 0 {
		t.Fatal("retained exited executable")
	}
}

func TestCachedNonGoExecutableDiscoversLateOpenSSL(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler required for shared-library fixture")
	}
	proc := t.TempDir()
	root := filepath.Join(proc, "1", "root")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(proc, "ssl.c")
	if err := os.WriteFile(source, []byte("int SSL_read(void) { return 0; }\nint SSL_write(void) { return 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-shared", "-fPIC", "-o", filepath.Join(root, "libssl.so.3"), source).CombinedOutput(); err != nil {
		t.Fatalf("compile SSL fixture: %v: %s", err, out)
	}
	cache := make(map[executableID]bool)
	id := executableID{}
	if got := classify(proc, 1, "/bin/sh", id, cache); got != tlsNone {
		t.Fatalf("before dlopen: %v", got)
	}
	if err := os.WriteFile(filepath.Join(proc, "1", "maps"), []byte("1000-2000 r-xp 0000 00:00 1 /libssl.so.3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := classify(proc, 1, "/bin/sh", id, cache); got != tlsGeneric {
		t.Fatalf("after dlopen: %v", got)
	}
	if err := os.Remove(filepath.Join(proc, "1", "maps")); err != nil {
		t.Fatal(err)
	}
	if got := classify(proc, 1, "/bin/sh", id, cache); got != tlsNone {
		t.Fatalf("after dlclose: %v", got)
	}
}

func BenchmarkGoTLSClassification(b *testing.B) {
	path, err := os.Executable()
	if err != nil {
		b.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		b.Fatal(err)
	}
	id := executableIdentity(st.Sys().(*syscall.Stat_t))
	for _, cached := range []bool{false, true} {
		name := "uncached"
		if cached {
			name = "cached"
		}
		b.Run(name, func(b *testing.B) {
			cache := make(map[executableID]bool)
			classify("/proc", int32(os.Getpid()), path, id, cache)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if !cached {
					clear(cache)
				}
				classify("/proc", int32(os.Getpid()), path, id, cache)
			}
		})
	}
}
