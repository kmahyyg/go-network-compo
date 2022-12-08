//go:build linux || dragonfly || freebsd || netbsd || openbsd || darwin

package dns

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// systemd-resolved: systemd-analyze cat-config systemd/resolved.conf
// or static file: /etc/resolv.conf
func Retrieve(manualSets bool) (map[string]string, error) {
	finalNSSettings := make(map[string]string, 0)
	rxInt := "^(?:[-+]?(?:0|[1-9][0-9]*))$"
	rxIntMatcher := regexp.MustCompile(rxInt)
	rxIP4 := `\d+\.\d+\.\d+\.\d+`
	rxIP4Matcher := regexp.MustCompile(rxIP4)

	if runtime.GOOS == "linux" {
		// additionally check systemd-resolved
		// loop read /proc
		// if /proc/[PID]/comm == systemd-resolved
		// execute "systemd-analyze cat-config systemd/resolved.conf"
		resolvedFound := false
		pids, err := os.ReadDir("/proc")
		if err != nil {
			return nil, err
		}
		for _, entry := range pids {
			// only need dir
			if !entry.IsDir() {
				continue
			}
			// only need pid
			if !rxIntMatcher.MatchString(entry.Name()) {
				continue
			}
			// check comm
			commFileName := "/proc/" + entry.Name() + "/comm"
			_, err := os.Stat(commFileName)
			if err != nil {
				continue
			}
			procName, err := ioutil.ReadFile(commFileName)
			if err != nil {
				continue
			}
			// strip \x0a then compare
			if bytes.Equal(procName[:len(procName)-1], []byte("systemd-resolved")) {
				resolvedFound = true
				break
			}
		}
		// if systemd-resolved is running, run blame
		if resolvedFound {
			cmd := exec.Command("/bin/sh", "-c", "resolvectl status")
			optData, err := cmd.Output()
			if err != nil {
				return nil, err
			}
			matchedStrs := rxIP4Matcher.FindAllString(string(optData), -1)
			if matchedStrs == nil {
				return nil, errors.New("internal error: match IP in resolvectl output")
			}
			// got matches
			finalNSSettings["systemd-resolved"] = strings.Join(matchedStrs, " ")
		}
	}
	{
		// must check /etc/resolv.conf
		_, err := os.Stat("/etc/resolv.conf")
		if err != nil {
			return nil, errors.New("resolv.conf not accessible")
		}
		resolvConfFD, err := os.Open("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		defer resolvConfFD.Close()
		// read line by line
		resolvLines := bufio.NewScanner(resolvConfFD)
		matchedIPaddr := make([]string, 0)
		for resolvLines.Scan() {
			// err handling
			if err := resolvLines.Err(); err == io.EOF {
				break
			} else if err != nil && err != io.EOF {
				return nil, err
			}
			curLineBytes := resolvLines.Bytes()
			// ignore comment
			if len(curLineBytes) == 0 {
				continue
			} else if curLineBytes[0] == byte('#') {
				continue
			} else {
				// match IP addr
				ret := rxIP4Matcher.FindString(resolvLines.Text())
				if len(ret) > 2 {
					matchedIPaddr = append(matchedIPaddr, ret)
				}
			}
		}
		finalNSSettings["resolv.conf"] = strings.Join(matchedIPaddr, " ")
	}
	return finalNSSettings, nil
}
