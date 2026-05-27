package main

import "os/exec"

func main() {
	_, _ = exec.Command("sh", "-c", "echo hi").CombinedOutput()
}
