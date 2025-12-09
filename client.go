package main

import (
	"bytes"
	"encoding/json"
	"image/jpeg"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kbinani/screenshot"
)

var (
	// CHANGE THIS WHEN USING REAL NETWORK
	serverIP      = "127.0.0.1:8080"
	clientID      = getClientID()
	uploadURL     = "http://" + serverIP + "/upload?id=" + clientID
	cmdPollURL    = "http://" + serverIP + "/cmd/poll?id=" + clientID
	cmdResultURL  = "http://" + serverIP + "/cmd/result?id=" + clientID
	procPollURL   = "http://" + serverIP + "/proc/poll?id=" + clientID
	procResultURL = "http://" + serverIP + "/proc/result?id=" + clientID
	filePollURL   = "http://" + serverIP + "/file/poll?id=" + clientID
	fileResultURL = "http://" + serverIP + "/file/result?id=" + clientID
	killURL       = "http://" + serverIP + "/kill?id=" + clientID
	edrCmdPollURL = "http://" + serverIP + "/edr/cmd/poll?id=" + clientID
)

/* ---------- TYPES ---------- */

type ShellCommand struct {
	Command string
}

type ShellResponse struct {
	Output string
}

type Process struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

type KillRequest struct {
	PID int `json:"pid"`
}

type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
	Path    string `json:"path"`
}

type FileRequest struct {
	Action string `json:"action"`
	Path   string `json:"path"`
}

type EDRCommand struct {
	Type string `json:"type"` // "isolate" or "unisolate"
}

/* ---------- HELPERS ---------- */

func getClientID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func sendSystemInfo() {
	info := map[string]string{
		"os":      runtime.GOOS,
		"version": runtime.Version(),
	}
	data, _ := json.Marshal(info)
	resp, err := http.Post(uploadURL, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Println("Isolax: sendSystemInfo failed:", err)
		return
	}
	resp.Body.Close()
	log.Println("Isolax: system info sent to", uploadURL)
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Isolax: %s %v FAILED: %v | out: %s", name, args, err, string(out))
	} else {
		log.Printf("Isolax: %s %v OK: %s", name, args, string(out))
	}
}

/* ---------- ISOLATION (WINDOWS + LINUX) ---------- */

func applyIsolation() {
	serverHost := strings.Split(serverIP, ":")[0]

	switch runtime.GOOS {
	case "windows":
		log.Println("Isolax: applying STRONG Windows isolation for", serverHost)

		// Turn firewall ON
		runCmd("netsh", "advfirewall", "set", "allprofiles", "state", "on")

		// GLOBAL POLICY: block inbound + outbound by default
		runCmd("netsh", "advfirewall", "set", "allprofiles",
			"firewallpolicy", "blockinbound,blockoutbound")

		// Remove old Isolax rules
		runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=IsolaxAllowOut")
		runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=IsolaxAllowIn")

		// Allow OUTBOUND to controller
		runCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name=IsolaxAllowOut", "dir=out", "action=allow",
			"remoteip="+serverHost, "profile=any", "protocol=any")

		// Allow INBOUND from controller (optional but nice)
		runCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name=IsolaxAllowIn", "dir=in", "action=allow",
			"remoteip="+serverHost, "profile=any", "protocol=any")

		log.Println("Isolax: Windows isolation ACTIVE (only", serverHost, "allowed)")

	case "linux":
		log.Println("Isolax: applying Linux isolation for", serverHost)

		// Clean previous chain if exists
		runCmd("iptables", "-D", "OUTPUT", "-j", "ISOLAX-OUT")
		runCmd("iptables", "-F", "ISOLAX-OUT")
		runCmd("iptables", "-X", "ISOLAX-OUT")

		// New chain
		runCmd("iptables", "-N", "ISOLAX-OUT")
		// allow traffic to controller
		runCmd("iptables", "-A", "ISOLAX-OUT", "-d", serverHost, "-j", "ACCEPT")
		// drop everything else
		runCmd("iptables", "-A", "ISOLAX-OUT", "-j", "DROP")
		// hook chain
		runCmd("iptables", "-A", "OUTPUT", "-j", "ISOLAX-OUT")

		log.Println("Isolax: Linux isolation ACTIVE (only", serverHost, "allowed)")

	default:
		log.Println("Isolax: isolation not implemented for OS:", runtime.GOOS)
	}
}

func removeIsolation() {
	switch runtime.GOOS {
	case "windows":
		log.Println("Isolax: removing Windows isolation (reset firewall)")
		runCmd("netsh", "advfirewall", "reset")

	case "linux":
		log.Println("Isolax: removing Linux isolation (iptables cleanup)")
		runCmd("iptables", "-D", "OUTPUT", "-j", "ISOLAX-OUT")
		runCmd("iptables", "-F", "ISOLAX-OUT")
		runCmd("iptables", "-X", "ISOLAX-OUT")

	default:
		log.Println("Isolax: removeIsolation not implemented for OS:", runtime.GOOS)
	}
}

func edrPoller() {
	log.Println("Isolax: EDR poller started →", edrCmdPollURL)

	for {
		resp, err := http.Get(edrCmdPollURL)
		if err != nil {
			log.Println("Isolax: edrPoll error:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cmd EDRCommand
		if json.Unmarshal(body, &cmd) != nil || cmd.Type == "" {
			time.Sleep(2 * time.Second)
			continue
		}

		log.Println("Isolax: received EDR command:", cmd.Type)

		if cmd.Type == "isolate" {
			applyIsolation()
		} else if cmd.Type == "unisolate" {
			removeIsolation()
		}

		time.Sleep(1 * time.Second)
	}
}

/* ---------- PROCESSES & FILES ---------- */

func listProcesses() ([]Process, error) {
	var processes []Process

	if runtime.GOOS == "windows" {
		out, err := exec.Command("tasklist").Output()
		if err != nil {
			return nil, err
		}
		lines := bytes.Split(out, []byte("\r\n"))
		for _, line := range lines[3:] {
			fields := bytes.Fields(line)
			if len(fields) >= 2 {
				pidStr := string(fields[1])
				pidInt, err := strconv.Atoi(pidStr)
				if err == nil {
					processes = append(processes, Process{PID: pidInt, Name: string(fields[0])})
				}
			}
		}
	} else {
		out, err := exec.Command("ps", "-e", "-o", "pid=,comm=").Output()
		if err != nil {
			return nil, err
		}
		lines := bytes.Split(out, []byte("\n"))
		for _, line := range lines {
			fields := bytes.Fields(line)
			if len(fields) >= 2 {
				pid, err := strconv.Atoi(string(fields[0]))
				if err == nil {
					processes = append(processes, Process{PID: pid, Name: string(fields[1])})
				}
			}
		}
	}

	return processes, nil
}

func listFiles(path string) ([]FileInfo, error) {
	var files []FileInfo

	if path == "/" && runtime.GOOS == "windows" {
		return getWindowsDrives()
	}

	entries, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	if path != "/" && path != "" {
		parent := filepath.Dir(path)
		files = append(files, FileInfo{
			Name:  "..",
			IsDir: true,
			Path:  parent,
		})
	}

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())
		files = append(files, FileInfo{
			Name:    entry.Name(),
			Size:    entry.Size(),
			IsDir:   entry.IsDir(),
			ModTime: entry.ModTime().Format("2006-01-02 15:04:05"),
			Path:    fullPath,
		})
	}

	return files, nil
}

func getWindowsDrives() ([]FileInfo, error) {
	var drives []FileInfo
	for i := 'A'; i <= 'Z'; i++ {
		drive := string(i) + ":\\"
		if _, err := os.Stat(drive); err == nil {
			drives = append(drives, FileInfo{
				Name:  drive,
				IsDir: true,
				Path:  drive,
			})
		}
	}
	return drives, nil
}

/* ---------- POLLERS ---------- */

func shellPoller() {
	for {
		resp, err := http.Get(cmdPollURL)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cmd ShellCommand
		if json.Unmarshal(body, &cmd) != nil || cmd.Command == "" {
			time.Sleep(2 * time.Second)
			continue
		}

		var out []byte
		if runtime.GOOS == "windows" {
			out, _ = exec.Command("cmd", "/C", cmd.Command).CombinedOutput()
		} else {
			out, _ = exec.Command("sh", "-c", cmd.Command).CombinedOutput()
		}

		res := ShellResponse{Output: string(out)}
		data, _ := json.Marshal(res)
		_, _ = http.Post(cmdResultURL, "application/json", bytes.NewReader(data))

		time.Sleep(1 * time.Second)
	}
}

func procPoller() {
	for {
		resp, err := http.Get(procPollURL)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cmd map[string]string
		if json.Unmarshal(body, &cmd) != nil || cmd["command"] != "list" {
			time.Sleep(300 * time.Millisecond)
			continue
		}

		procs, err := listProcesses()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		var out string
		for _, p := range procs {
			out += strconv.Itoa(p.PID) + " " + p.Name + "\n"
		}

		payload := map[string]string{"output": out}
		data, _ := json.Marshal(payload)
		_, _ = http.Post(procResultURL, "application/json", bytes.NewReader(data))

		time.Sleep(300 * time.Millisecond)
	}
}

func filePoller() {
	for {
		resp, err := http.Get(filePollURL)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var req FileRequest
		if json.Unmarshal(body, &req) != nil || req.Action == "" {
			time.Sleep(300 * time.Millisecond)
			continue
		}

		switch req.Action {
		case "list":
			files, err := listFiles(req.Path)
			if err != nil {
				files = []FileInfo{}
			}
			data, _ := json.Marshal(files)
			_, _ = http.Post(fileResultURL, "application/json", bytes.NewReader(data))
		}

		time.Sleep(300 * time.Millisecond)
	}
}

func processKiller() {
	for {
		resp, err := http.Get(killURL)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var req KillRequest
		if json.Unmarshal(body, &req) != nil || req.PID == 0 {
			time.Sleep(3 * time.Second)
			continue
		}

		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/PID", strconv.Itoa(req.PID), "/F").Run()
		} else {
			if p, err := os.FindProcess(req.PID); err == nil {
				_ = p.Kill()
			}
		}

		time.Sleep(3 * time.Second)
	}
}

/* ---------- MAIN ---------- */

func main() {
	log.Printf("[Isolax] client %s starting, server %s, OS %s", clientID, serverIP, runtime.GOOS)

	// heartbeat for system info (so server always sees client)
	go func() {
		for {
			sendSystemInfo()
			time.Sleep(10 * time.Second)
		}
	}()

	go edrPoller()
	go shellPoller()
	go procPoller()
	go filePoller()
	go processKiller()

	for {
		img, err := screenshot.CaptureDisplay(0)
		if err != nil {
			log.Println("Isolax: screenshot failed:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 75}); err != nil {
			log.Println("Isolax: jpeg encode failed:", err)
			continue
		}

		resp, err := http.Post(uploadURL, "image/jpeg", &buf)
		if err == nil {
			resp.Body.Close()
		} else {
			log.Println("Isolax: upload frame failed:", err)
		}

		time.Sleep(100 * time.Millisecond)
	}
}
