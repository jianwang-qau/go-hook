// SPDX-License-Identifier: GPL-2.0
//
// main.go
//
// (C) 2024 Jian Wang
//

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jessevdk/go-flags"
)

type Option struct {
	AuthHook string   `long:"auth-hook" required:"true"`
	Domains  []string `short:"d" long:"domain" required:"true"`
}

func main() {
	var opt Option
	flags.Parse(&opt)

	authHook := opt.AuthHook
	domains := opt.Domains
	var domainSlice []string

	for _, item := range domains {
		domainSlice = append(domainSlice, strings.Split(item, ",")...)
	}

	allDomains := strings.Join(domainSlice, ",")
	domainNum := len(domainSlice)
	domainStr := domainSlice[0]
	if domainNum == 2 {
		domainStr = fmt.Sprintf("%s and %s", domainSlice[0], domainSlice[1])
	} else if domainNum > 2 {
		domainStr = fmt.Sprintf("%s and 2 more domains", domainSlice[0])
	}
	fmt.Printf("Learning hook process for %s\n", domainStr)

	file_info, err := os.Stat(authHook)
	if os.IsNotExist(err) {
		printlnErr("Unable to find auth-hook command %s in the PATH.", authHook)
		printlnErr("(PATH is %s)", os.Getenv("PATH"))
		os.Exit(0)
	}

	file_mode := file_info.Mode()
	perm := file_mode.Perm()
	flag := perm & os.FileMode(73)
	if uint32(flag) != uint32(73) {
		printlnErr("auth-hook command %s exists, but is not executable.", authHook)
		os.Exit(0)
	}

	errTotal := 0

	for i, domain := range domainSlice {
		validation, _ := uuid.NewRandom()
		remainingChallenges := domainNum - i - 1
		errTotal += processAuthHook(authHook, domain, validation.String(), remainingChallenges, allDomains)
	}
}

// process auth hook
func processAuthHook(authHook string, domain string, validation string, remainingChallenges int, allDomains string) (errCode int) {
	errCode = 0
	hookPath, _ := filepath.Abs(authHook)
	cmd := exec.Command(hookPath)

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	cmd.Env = []string{
		"HOOK_DOMAIN=" + domain,
		"HOOK_VALIDATION=" + validation,
		"HOOK_REMAINING_CHALLENGES=" + strconv.Itoa(remainingChallenges),
		"HOOK_ALL_DOMAINS=" + allDomains,
	}

	err := cmd.Run()
	if err != nil {
		errCode = 1
		printlnErr(err.Error())
		return
	}

	outStr := strings.TrimRight(outb.String(), "\n")
	errStr := strings.TrimRight(errb.String(), "\n")

	if len(outStr) > 0 {
		fmt.Printf("Hook '--auth-hook' for %s ran with output:\n", domain)
		fmt.Println(outStr)
	}

	if len(errStr) > 0 {
		errCode = 1
		printlnErr("Hook '--auth-hook' for %s ran with error output:", domain)
		printlnErr(errStr)
	}

	return
}

// print error msg
func printlnErr(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "\033[31m%s\033[0m\n", msg)
}
