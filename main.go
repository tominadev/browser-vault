package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type User struct {
	Username            string            `json:"username"`
	Salt                string            `json:"salt"`
	AuthVerifier        string            `json:"auth_verifier"`
	PublicKey           string            `json:"public_key"`
	EncryptedUserKey    string            `json:"encrypted_user_key"`
	EncryptedPrivateKey string            `json:"encrypted_private_key"`
	AdminWraps          map[string]string `json:"admin_wraps"`
	Admin               bool              `json:"admin"`
}

type FileMeta struct {
	ID         string    `json:"id"`
	Owner      string    `json:"owner"`
	Name       string    `json:"name"`
	StoredName string    `json:"-"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
	KeyPackage string    `json:"key_package"`
}

type database struct {
	Users map[string]User     `json:"users"`
	Files map[string]FileMeta `json:"files"`
}

type app struct {
	mu       sync.RWMutex
	data     database
	dataPath string
	filesDir string
	sessions map[string]string
}

func main() {
	root := env("BROWSER_VAULT_DATA_DIR", "./data")
	a := &app{dataPath: filepath.Join(root, "db.json"), filesDir: filepath.Join(root, "files"), sessions: map[string]string{}}
	if err := a.load(); err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(a.filesDir, 0700); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.index)
	mux.HandleFunc("/api/auth-info", a.authInfo)
	mux.HandleFunc("/api/register", a.register)
	mux.HandleFunc("/api/login", a.login)
	mux.HandleFunc("/api/me", a.me)
	mux.HandleFunc("/api/account/password", a.changePassword)
	mux.HandleFunc("/api/logout", a.logout)
	mux.HandleFunc("/api/admin-keys", a.adminKeys)
	mux.HandleFunc("/api/admin/users", a.adminUsers)
	mux.HandleFunc("/api/files", a.files)
	mux.HandleFunc("/api/files/", a.file)
	server := &http.Server{Addr: env("BROWSER_VAULT_ADDR", ":8080"), Handler: securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute}
	log.Printf("browser vault listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func (a *app) load() error {
	raw, err := os.ReadFile(a.dataPath)
	if errors.Is(err, os.ErrNotExist) {
		a.data = database{Users: map[string]User{}, Files: map[string]FileMeta{}}
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &a.data); err != nil {
		return err
	}
	if a.data.Users == nil {
		a.data.Users = map[string]User{}
	}
	if a.data.Files == nil {
		a.data.Files = map[string]FileMeta{}
	}
	return nil
}

func (a *app) saveLocked() error {
	raw, err := json.MarshalIndent(a.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := a.dataPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.dataPath)
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func decodeJSON(r *http.Request, value any) error {
	if r.Body == nil {
		return errors.New("empty request")
	}
	return json.NewDecoder(io.LimitReader(r.Body, 2<<20)).Decode(value)
}

type registerRequest struct {
	Username, Salt, AuthVerifier, PublicKey, EncryptedUserKey, EncryptedPrivateKey string
	AdminWraps                                                                     map[string]string `json:"admin_wraps"`
}

func (a *app) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		jsonResponse(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if len(req.Username) < 3 || len(req.Username) > 64 || req.Salt == "" || req.AuthVerifier == "" || req.PublicKey == "" || req.EncryptedUserKey == "" || req.EncryptedPrivateKey == "" {
		jsonResponse(w, 400, map[string]string{"error": "missing registration fields"})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.data.Users[req.Username]; ok {
		jsonResponse(w, 409, map[string]string{"error": "username already exists"})
		return
	}
	admin := len(a.data.Users) == 0
	a.data.Users[req.Username] = User{Username: req.Username, Salt: req.Salt, AuthVerifier: req.AuthVerifier, PublicKey: req.PublicKey, EncryptedUserKey: req.EncryptedUserKey, EncryptedPrivateKey: req.EncryptedPrivateKey, AdminWraps: req.AdminWraps, Admin: admin}
	if err := a.saveLocked(); err != nil {
		jsonResponse(w, 500, map[string]string{"error": "save failed"})
		return
	}
	a.startSessionLocked(w, req.Username)
	jsonResponse(w, 201, map[string]any{"username": req.Username, "admin": admin})
}

func (a *app) authInfo(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.URL.Query().Get("username"))
	a.mu.RLock()
	user, ok := a.data.Users[username]
	a.mu.RUnlock()
	if !ok {
		jsonResponse(w, 404, map[string]string{"error": "user not found"})
		return
	}
	jsonResponse(w, 200, map[string]string{"salt": user.Salt})
}

func (a *app) me(w http.ResponseWriter, r *http.Request) {
	username := a.currentUser(r)
	if username == "" {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "sign in required"})
		return
	}
	a.mu.RLock()
	user := a.data.Users[username]
	a.mu.RUnlock()
	jsonResponse(w, http.StatusOK, user)
}

func (a *app) changePassword(w http.ResponseWriter, r *http.Request) {
	username := a.currentUser(r)
	if username == "" {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{"error": "sign in required"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct{ Salt, AuthVerifier, EncryptedUserKey, EncryptedPrivateKey string }
	if err := decodeJSON(r, &req); err != nil || req.Salt == "" || req.AuthVerifier == "" || req.EncryptedUserKey == "" || req.EncryptedPrivateKey == "" {
		jsonResponse(w, 400, map[string]string{"error": "invalid password update"})
		return
	}
	a.mu.Lock()
	user := a.data.Users[username]
	user.Salt, user.AuthVerifier, user.EncryptedUserKey, user.EncryptedPrivateKey = req.Salt, req.AuthVerifier, req.EncryptedUserKey, req.EncryptedPrivateKey
	a.data.Users[username] = user
	err := a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "save failed"})
		return
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct{ Username, AuthVerifier string }
	if err := decodeJSON(r, &req); err != nil {
		jsonResponse(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	a.mu.RLock()
	user, ok := a.data.Users[req.Username]
	a.mu.RUnlock()
	if !ok || req.AuthVerifier == "" || req.AuthVerifier != user.AuthVerifier {
		jsonResponse(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	a.startSession(w, req.Username)
	jsonResponse(w, 200, map[string]any{"username": user.Username, "admin": user.Admin})
}
func (a *app) startSession(w http.ResponseWriter, user string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.startSessionLocked(w, user)
}
func (a *app) startSessionLocked(w http.ResponseWriter, user string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	a.sessions[token] = user
	http.SetCookie(w, &http.Cookie{Name: "bv_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 86400})
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("bv_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "bv_session", Path: "/", MaxAge: -1, HttpOnly: true})
	jsonResponse(w, 200, map[string]bool{"ok": true})
}
func (a *app) currentUser(r *http.Request) string {
	c, err := r.Cookie("bv_session")
	if err != nil {
		return ""
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.sessions[c.Value]
}
func (a *app) adminKeys(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	keys := map[string]string{}
	for name, user := range a.data.Users {
		if user.Admin {
			keys[name] = user.PublicKey
		}
	}
	jsonResponse(w, 200, keys)
}

func (a *app) adminUsers(w http.ResponseWriter, r *http.Request) {
	if user := a.currentUser(r); user == "" {
		jsonResponse(w, 401, map[string]string{"error": "sign in required"})
		return
	} else {
		a.mu.RLock()
		isAdmin := a.data.Users[user].Admin
		a.mu.RUnlock()
		if !isAdmin {
			jsonResponse(w, 403, map[string]string{"error": "administrator access required"})
			return
		}
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	users := make([]User, 0, len(a.data.Users))
	for _, user := range a.data.Users {
		users = append(users, user)
	}
	jsonResponse(w, 200, users)
}

func (a *app) files(w http.ResponseWriter, r *http.Request) {
	user := a.currentUser(r)
	if user == "" {
		jsonResponse(w, 401, map[string]string{"error": "sign in required"})
		return
	}
	if r.Method == http.MethodGet {
		a.mu.RLock()
		list := []FileMeta{}
		for _, file := range a.data.Files {
			if file.Owner == user {
				list = append(list, file)
			}
		}
		a.mu.RUnlock()
		jsonResponse(w, 200, list)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 200<<20)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		name, err := url.QueryUnescape(r.Header.Get("X-File-Name"))
		if err != nil || name == "" || r.Header.Get("X-Key-Package") == "" {
			jsonResponse(w, 400, map[string]string{"error": "encrypted stream metadata is missing"})
			return
		}
		meta, err := a.saveEncrypted(user, filepath.Base(name), r.Header.Get("X-Key-Package"), r.Body)
		if err != nil {
			jsonResponse(w, 500, map[string]string{"error": "encrypted upload failed"})
			return
		}
		jsonResponse(w, 201, meta)
		return
	}
	if err := r.ParseMultipartForm(200 << 20); err != nil {
		jsonResponse(w, 413, map[string]string{"error": "encrypted upload is too large"})
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		jsonResponse(w, 400, map[string]string{"error": "encrypted file is missing"})
		return
	}
	defer file.Close()
	meta, err := a.saveEncrypted(user, filepath.Base(header.Filename), r.Header.Get("X-Key-Package"), file)
	if err != nil {
		jsonResponse(w, 500, map[string]string{"error": "encrypted upload failed"})
		return
	}
	jsonResponse(w, 201, meta)
}

func (a *app) saveEncrypted(user, name, keyPackage string, input io.Reader) (FileMeta, error) {
	idBytes := make([]byte, 16)
	_, _ = rand.Read(idBytes)
	id := hex.EncodeToString(idBytes)
	stored := filepath.Join(a.filesDir, id+".blob")
	out, err := os.OpenFile(stored, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return FileMeta{}, err
	}
	size, copyErr := io.Copy(out, input)
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(stored)
		return FileMeta{}, errors.New("encrypted upload failed")
	}
	meta := FileMeta{ID: id, Owner: user, Name: name, StoredName: stored, Size: size, CreatedAt: time.Now().UTC(), KeyPackage: keyPackage}
	a.mu.Lock()
	a.data.Files[id] = meta
	err = a.saveLocked()
	a.mu.Unlock()
	if err != nil {
		_ = os.Remove(stored)
		return FileMeta{}, err
	}
	return meta, nil
}
func (a *app) file(w http.ResponseWriter, r *http.Request) {
	user := a.currentUser(r)
	if user == "" {
		http.Error(w, "unauthorized", 401)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/files/")
	a.mu.RLock()
	meta, ok := a.data.Files[id]
	a.mu.RUnlock()
	if !ok || meta.Owner != user {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, meta.StoredName)
}
func (a *app) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "web/index.html")
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}
