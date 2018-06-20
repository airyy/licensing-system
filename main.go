package main

import (
	"net/http"
	"github.com/icza/gowut/gwu"
	"sync"
	"io/ioutil"
	"encoding/json"
	"strings"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"github.com/dchest/safefile"
	"io"
)

type loginInfo struct {
	Username string
	Hash     string
}

var mainServer http.Server
var loginLock sync.RWMutex
var loginPath string
var loginMap map[string]loginInfo
var keyPath string
var keyData string

func main() {
	mainWindow := gwu.NewWindow("Licensing-System", "Licensing-System")
	mainTab := gwu.NewTabPanel()
	initPanel := gwu.NewPanel()
	mainTab.AddString("Initialize Database", initPanel)
	serverPanel := gwu.NewPanel()
	mainTab.AddString("Start/Stop Server", serverPanel)
	activationPanel := gwu.NewPanel()
	mainTab.AddString("Activation Settings", activationPanel)
	initPanel.Add(gwu.NewLabel("Local path to login database:"))
	dataPathTextBox := gwu.NewTextBox("")
	initPanel.Add(dataPathTextBox)
	initPanel.Add(gwu.NewLabel("Local path to key database:"))
	keyPathTextBox := gwu.NewTextBox("")
	initPanel.Add(keyPathTextBox)
	initPanel.AddVSpace(10)
	initButton := gwu.NewButton("Initialize Database")
	initPanel.Add(initButton)
	initPanel.AddVSpace(10)
	initErrorLabel := gwu.NewLabel("")
	initPanel.Add(initErrorLabel)
	initButton.AddEHandlerFunc(func(e gwu.Event) {
		keyPath = keyPathTextBox.Text()
		loginPath = dataPathTextBox.Text()
		err := initData()
		if err != nil {
			initErrorLabel.SetText(err.Error())
			e.MarkDirty(initErrorLabel)
		} else {
			initErrorLabel.SetText("Success!")
			initButton.SetEnabled(false)
			e.MarkDirty(initErrorLabel)
			e.MarkDirty(initButton)
		}
	}, gwu.ETypeClick)
	serverPanel.Add(gwu.NewLabel("Port:"))
	portTextBox := gwu.NewTextBox("")
	serverPanel.Add(portTextBox)
	serverPanel.AddVSpace(10)
	startButton := gwu.NewButton("Start!")
	serverPanel.Add(startButton)
	stopButton := gwu.NewButton("Stop!")
	stopButton.SetEnabled(false)
	serverPanel.Add(stopButton)
	startButton.AddEHandlerFunc(func(e gwu.Event) {
		go startServer(portTextBox.Text())
		startButton.SetEnabled(false)
		stopButton.SetEnabled(true)
		e.MarkDirty(startButton)
		e.MarkDirty(stopButton)
	}, gwu.ETypeClick)
	stopButton.AddEHandlerFunc(func(e gwu.Event) {
		stopServer()
		startButton.SetEnabled(true)
		stopButton.SetEnabled(false)
		e.MarkDirty(startButton)
		e.MarkDirty(stopButton)
	}, gwu.ETypeClick)
	activationPanel.Add(gwu.NewLabel("Automatic Activation:"))
	activationPanel.AddVSpace(10)
	activationPanel.Add(gwu.NewLabel("Key:"))
	keyTextBox := gwu.NewTextBox("")
	activationPanel.Add(keyTextBox)
	activationPanel.AddVSpace(10)
	addKeyButton := gwu.NewButton("Add Key!")
	activationPanel.Add(addKeyButton)
	removeKeyButton := gwu.NewButton("Remove Key!")
	activationPanel.Add(removeKeyButton)
	activationPanel.AddVSpace(10)
	activationPanel.Add(gwu.NewLabel("Manual Activation:"))
	activationPanel.AddVSpace(10)
	activationPanel.Add(gwu.NewLabel("Username:"))
	usernameTextBox := gwu.NewTextBox("")
	activationPanel.Add(usernameTextBox)
	activationPanel.Add(gwu.NewLabel("Password:"))
	passwordTextBox := gwu.NewPasswBox("")
	activationPanel.Add(passwordTextBox)
	activationPanel.AddVSpace(10)
	addLoginButton := gwu.NewButton("Add Login!")
	activationPanel.Add(addLoginButton)
	removeLoginButton := gwu.NewButton("Remove Login!")
	activationPanel.Add(removeLoginButton)
	activationPanel.AddVSpace(10)
	activationErrorLabel := gwu.NewLabel("")
	activationPanel.Add(activationErrorLabel)
	addKeyButton.AddEHandlerFunc(func(e gwu.Event) {
		err := addKey(keyTextBox.Text())
		if err != nil {
			activationErrorLabel.SetText(err.Error())
			e.MarkDirty(activationErrorLabel)
		} else {
			activationErrorLabel.SetText("Success!")
			e.MarkDirty(activationErrorLabel)
		}
	}, gwu.ETypeClick)
	removeKeyButton.AddEHandlerFunc(func(e gwu.Event) {
		err := removeKey(keyTextBox.Text())
		if err != nil {
			activationErrorLabel.SetText(err.Error())
			e.MarkDirty(activationErrorLabel)
		} else {
			activationErrorLabel.SetText("Success!")
			e.MarkDirty(activationErrorLabel)
		}
	}, gwu.ETypeClick)
	addLoginButton.AddEHandlerFunc(func(e gwu.Event) {
		err := addLogin(usernameTextBox.Text(), passwordTextBox.Text())
		if err != nil {
			activationErrorLabel.SetText(err.Error())
			e.MarkDirty(activationErrorLabel)
		} else {
			activationErrorLabel.SetText("Success!")
			e.MarkDirty(activationErrorLabel)
		}
	}, gwu.ETypeClick)
	removeLoginButton.AddEHandlerFunc(func(e gwu.Event) {
		err := removeLogin(usernameTextBox.Text())
		if err != nil {
			activationErrorLabel.SetText(err.Error())
			e.MarkDirty(activationErrorLabel)
		} else {
			activationErrorLabel.SetText("Success!")
			e.MarkDirty(activationErrorLabel)
		}
	}, gwu.ETypeClick)
	mainWindow.Add(mainTab)
	guiServer := gwu.NewServer("", ":8080")
	guiServer.AddWin(mainWindow)
	guiServer.Start()
}

func initData() error {
	data, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return err
	}
	keyData = string(data)
	loginFile, err := ioutil.ReadFile(loginPath)
	if err != nil {
		return err
	}
	if strings.Contains(string(loginFile), "{") == false {
		loginMap = make(map[string]loginInfo)
		return nil
	}
	err = json.Unmarshal([]byte(loginFile), &loginMap)
	if err != nil {
		return err
	}
	return nil
}

func startServer(port string) {
	mainMux := http.NewServeMux()
	mainMux.HandleFunc("/login/", loginHandler)
	mainMux.HandleFunc("/register/", registerHandler)
	mainServer = http.Server{Addr: ":" + port, Handler: mainMux}
	mainServer.ListenAndServe()
}

func stopServer() {
	mainServer.Shutdown(nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Path
	url = strings.TrimPrefix(url, "/login/")
	parts := strings.Split(url, ":")
	if len(parts) != 2 {
		w.Write([]byte("Failed!"))
	} else {
		if checkLogin(parts[0], parts[1]) == nil {
			w.Write([]byte("Success!"))
		} else {
			w.Write([]byte("Failed!"))
		}
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Path
	url = strings.TrimPrefix(url, "/register/")
	parts := strings.Split(url, ":")
	if len(parts) != 3 {
		w.Write([]byte("Failed!"))
	} else {
		if checkRegister(parts[0], parts[1], parts[2]) == nil {
			w.Write([]byte("Success!"))
			removeKey(parts[0])
		} else {
			w.Write([]byte("Failed!"))
		}
	}
}

func checkLogin(username, password string) error {
	loginLock.Lock()
	defer loginLock.Unlock()
	login, ok := loginMap[username]
	if !ok {
		return errors.New("failed")
	}
	err := bcrypt.CompareHashAndPassword([]byte(login.Hash), []byte(password))
	if err != nil {
		return errors.New("failed")
	}
	return nil
}

func checkRegister(key, username, password string) error {
	if strings.Contains(keyData, key) == true {
		addLogin(username, password)
	} else {
		return errors.New("failed")
	}
	return nil
}

func addKey(key string) error {
	keyData = keyData + key + "\n"
	write, err := safefile.Create(keyPath, 0660)
	if err != nil {
		return err
	}
	defer write.Close()
	_, err = io.WriteString(write, keyData)
	if err != nil {
		return err
	}
	err = write.Commit()
	if err != nil {
		return err
	}
	return nil
}

func removeKey(key string) error {
	keyData = strings.Replace(keyData, key+"\n", "", 1)
	write, err := safefile.Create(keyPath, 0660)
	if err != nil {
		return err
	}
	defer write.Close()
	_, err = io.WriteString(write, keyData)
	if err != nil {
		return err
	}
	err = write.Commit()
	if err != nil {
		return err
	}
	return nil
}

func addLogin(username, password string) error {
	loginLock.Lock()
	defer loginLock.Unlock()
	_, ok := loginMap[username]
	if ok {
		return errors.New("user already exists")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	loginMap[username] = loginInfo{username, string(hash)}
	data, err := json.Marshal(loginMap)
	if err != nil {
		return err
	}
	write, err := safefile.Create(loginPath, 0660)
	if err != nil {
		return err
	}
	defer write.Close()
	_, err = io.WriteString(write, string(data))
	if err != nil {
		return err
	}
	err = write.Commit()
	if err != nil {
		return err
	}
	return nil
}

func removeLogin(username string) error {
	loginLock.Lock()
	defer loginLock.Unlock()
	_, ok := loginMap[username]
	if !ok {
		return errors.New("user doesn't exist")
	}
	delete(loginMap, username)
	data, err := json.Marshal(loginMap)
	if err != nil {
		return err
	}
	write, err := safefile.Create(loginPath, 0660)
	if err != nil {
		return err
	}
	defer write.Close()
	_, err = io.WriteString(write, string(data))
	if err != nil {
		return err
	}
	err = write.Commit()
	if err != nil {
		return err
	}
	return nil
}
