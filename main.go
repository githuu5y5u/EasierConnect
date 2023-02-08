package main

import (
	"EasierConnect/buildconfig"
	"EasierConnect/core"
	"EasierConnect/gui"
	"EasierConnect/listener"
	"flag"
	"io"
	"log"
	"os"
)

func setLogger() {
	os.Remove("Easier.log")
	f, err := os.OpenFile("Easier.log", os.O_RDWR|os.O_CREATE|os.O_APPEND|os.O_SYNC, 0666)
	if err != nil {
		panic(err)
	}

	listener.ConsoleListenerInstance = listener.ConsoleListener{}

	wrt := io.MultiWriter(os.Stdout, f, &listener.ConsoleListenerInstance)
	log.SetOutput(wrt)
}

func main() {
	// CLI args
	host, port, username, password, twfId := "", 0, "", "", ""
	flag.StringVar(&host, "server", "", "EasyConnect server address (e.g. vpn.nju.edu.cn, sslvpn.sysu.edu.cn)")
	flag.StringVar(&username, "username", "", "Your username")
	flag.StringVar(&password, "password", "", "Your password")
	flag.StringVar(&core.SocksBind, "socks-bind", ":1080", "The addr socks5 server listens on (e.g. 0.0.0.0:1080)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")
	flag.IntVar(&port, "port", 443, "EasyConnect port address (e.g. 443)")
	core.DebugDump = false
	core.ParseServConfig = true
	noGui := false
	flag.BoolVar(&core.DebugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.BoolVar(&core.ParseServConfig, "parse", true, "parse server buildconfig")
	flag.BoolVar(&noGui, "noGui", false, "Open without GUI")
	flag.Parse()

	setLogger()

	if host == "" || ((username == "" || password == "") && twfId == "") {
		if noGui || buildconfig.NoGui() {
			log.Printf("Starting as ECAgent mode. For more infomations: `EasierConnect --help`.\n")
			core.StartECAgent()
		} else {
			log.Printf("Starting GUI.  For more infomations: `EasierConnect --help`.\n")
			//TODO:: DECREASE THE SIZE ~ 30MB = GUI
			//TODO:: ANDROID & IOS support
			gui.StartGUI()
		}
	} else {
		core.StartClient(host, port, username, password, twfId)
	}
}
