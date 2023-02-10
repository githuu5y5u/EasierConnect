package main

import (
	"EasierConnect.gui/component"
	"EasierConnect.gui/listener"
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
	setLogger()
	component.EasierConnectUI()
}
