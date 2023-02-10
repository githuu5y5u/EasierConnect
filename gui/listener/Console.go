package listener

import (
	"log"
	"os"
)

var ConsoleListenerInstance ConsoleListener

type ConsoleListener struct {
	ConsoleListeners []chan string
}

// implement of io.Writer (called from logger)
func (c *ConsoleListener) Write(data []byte) (n int, err error) {
	for _, channel := range c.ConsoleListeners {
		channel <- string(data)
	}
	return len(data), nil
}

var ConsoleWriterInstance ConsoleWriter

type ConsoleWriter struct {
	ConsoleWriterHandle *os.File
}

func (c *ConsoleWriter) SetupPipe() {
	var err error
	var pipeRx *os.File

	pipeRx, c.ConsoleWriterHandle, err = os.Pipe()
	if err != nil {
		log.Fatal(err)
	}

	os.Stdin = pipeRx
}

func (c *ConsoleWriter) WriteToConsole(data []byte) {
	_, err := c.ConsoleWriterHandle.Write(data)
	if err != nil {
		panic(err)
	}

	defer func() {
		c.ConsoleWriterHandle.Close()
		c.SetupPipe()
	}()
}
