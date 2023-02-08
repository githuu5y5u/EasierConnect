package component

import (
	"EasierConnect/core"
	"EasierConnect/core/config"
	"EasierConnect/gui/resources"
	"EasierConnect/listener"
	"encoding/base64"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/validation"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"image/color"
	"log"
	"math"
	"strconv"
	"time"
)

const (
	AppLabel = "EasierConnect"
	APPID    = "github.com/lyc8503/EasierConnect"
)

var (
	Connected    = false
	WindowHeight = 640
	WindowWidth  = 400
)

func EasierConnectUI() {
	ecApp := app.NewWithID(APPID)

	//TODO:: BETTER ICON
	staticIcon, err := base64.StdEncoding.DecodeString(resources.IconBase64)
	if err == nil {
		ecApp.SetIcon(&fyne.StaticResource{StaticName: "icon", StaticContent: staticIcon})
	}
	pref := ecApp.Preferences()
	mainWindow := ecApp.NewWindow(AppLabel)
	mainWindow.Resize(fyne.Size{Height: float32(WindowHeight), Width: float32(WindowWidth)})

	confirmation := ecApp.NewWindow("Confirmation")

	confirmation.CenterOnScreen()
	confirmation.SetFixedSize(true)
	confirmation.Resize(fyne.Size{Height: 200, Width: 400})
	confirmation.SetContent(container.New(layout.NewMaxLayout()))
	confirmation.SetCloseIntercept(func() {
		for _, overlay := range confirmation.Canvas().Overlays().List() {
			confirmation.Canvas().Overlays().Remove(overlay)
		}

		confirmation.Hide()
	})

	validator1 := validation.NewRegexp(`[\w\d.]+`, "Invalid Url")
	validator2 := validation.NewRegexp(`\w+`, "Can't be empty")
	validator3 := validation.NewRegexp(`^[1-9]\d+$`, "Should Be ecApp number")
	validator4 := validation.NewRegexp(`:\d+$`, "eg: 127.0.0.1:1080")

	url := widget.NewEntry()
	url.SetPlaceHolder("vpn.domain.com") //Hint
	url.Validator = validator1
	url.SetText(pref.StringWithFallback("Url", "")) //Save user input after exit

	port := widget.NewEntry()
	port.SetPlaceHolder("443")
	port.SetText(pref.StringWithFallback("Port", "443"))
	port.Validator = validator3

	username := widget.NewEntry()
	username.SetPlaceHolder("UserName")
	username.Validator = validator2
	username.SetText(pref.StringWithFallback("UserName", ""))

	passwd := widget.NewPasswordEntry()
	passwd.SetPlaceHolder("Password")
	passwd.Validator = validator2
	passwd.SetText(pref.StringWithFallback("Password", ""))

	twfID := widget.NewEntry()
	twfID.SetPlaceHolder("twfID")
	twfID.Validator = validator2
	twfID.SetText(pref.StringWithFallback("twfID", ""))

	socks5 := widget.NewEntry()
	socks5.SetPlaceHolder("127.0.0.1:1080")
	socks5.Validator = validator4
	socks5.SetText(pref.StringWithFallback("Socks5", "127.0.0.1:1080"))

	form := &widget.Form{}

	form.CancelText = "Exit"
	form.SubmitText = "Connect"
	form.OnCancel = func() {
		mainWindow.Close()
		ecApp.Quit()
	}

	console := container.NewVBox()
	consoleScroll := container.NewVScroll(console)

	// we can also append items
	loginContainer := container.New(layout.NewPaddedLayout(), form)

	mode := widget.NewSelect([]string{"UserPassword", "twfID", "ECAgent"}, func(value string) {
		log.Println("Mode switch to: ", value)
		form.Items = form.Items[:0]

		form.Disable()
		form.Refresh()

		switch {
		case value == "UserPassword":
			form.Append("Url", url)
			form.Append("Port", port)
			form.Append("Socks5 Listen", socks5)
			form.Append("UserName", username)
			form.Append("PassWord", passwd)
			twfID.Text = ""
			twfID.Refresh()

			consoleScroll.SetMinSize(fyne.Size{Height: 160, Width: 0})
			break
		case value == "twfID":
			form.Append("Url", url)
			form.Append("Port", port)
			form.Append("Socks5 Listen", socks5)
			form.Append("twfID", twfID)

			consoleScroll.SetMinSize(fyne.Size{Height: 220, Width: 0})
			break
		case value == "ECAgent":
			log.Println("!!! You need to Click [Advance->Proceed to localhost(unsafe)] on Chrome to use ECAgent mode. !!!")
			log.Println("!!! You can turn on this flag at chrome://flags/#allow-insecure-localhost for convenience. !!!")
			form.Append("Socks5 Listen", socks5)

			consoleScroll.SetMinSize(fyne.Size{Height: 404, Width: 0})
			break
		}

		form.Enable()
		form.Refresh()
		pref.SetString("loginMode", value)
	})

	mode.PlaceHolder = "UserPassword"
	mode.SetSelected(pref.StringWithFallback("loginMode", "UserPassword"))

	form.OnSubmit = func() {
		pref.SetString("Url", url.Text)
		pref.SetString("Port", port.Text)
		pref.SetString("UserName", username.Text)
		//		pref.SetString("Password", passwd.Text)		TODO::Encrypt password
		pref.SetString("Socks5", socks5.Text)

		run := func() {
			if !Connected {
				form.SubmitText = "DisConnect"
				form.Disable()
				form.Refresh()
				Connected = true

				log.Println("Connecting.....")

				mode.Refresh()

				log.Println("Current Mode: ", mode.Selected)

				if mode.Selected == "ECAgent" {
					core.StartECAgent()
				} else {
					portInt, err := strconv.Atoi(port.Text)
					if err != nil {
						log.Fatal("Cannot parse port!")
					}

					core.StartClient(url.Text, portInt, username.Text, passwd.Text, twfID.Text)
				}

			} else {
				form.SubmitText = "Connect"
				form.Refresh()
				Connected = false

				//TODO:: Disconnect
			}
		}

		go run()
	}

	form.Enable()
	form.Refresh()

	sep := widget.NewSeparator()

	var rxChan = make(chan string, 64)

	listener.ConsoleListenerInstance.ConsoleListeners = append(listener.ConsoleListenerInstance.ConsoleListeners, rxChan)

	rx := func() {
		for {
			width := 52
			result := <-rxChan

			if len(console.Objects) > 50 {
				console.Remove(console.Objects[0])
			}

			for i := 0; i < len(result)-1; i += width {
				if i > len(result) {
					break
				}
				console.Add(&canvas.Text{
					Text: result[i:int32(math.Min(float64(i+width), float64(len(result)-1)))],
					Color: color.RGBA{
						R: 37,
						G: 150,
						B: 190,
						A: 255,
					},
					TextSize:  12,
					TextStyle: fyne.TextStyle{Monospace: true, Symbol: true},
				})
			}

			console.Refresh()

			consoleScroll.ScrollToBottom()
		}
	}

	go rx()

	listener.ConsoleWriterInstance = listener.ConsoleWriter{}
	listener.ConsoleWriterInstance.SetupPipe()

	input := widget.NewEntry()
	input.OnSubmitted = func(str string) {
		log.Println("Sending to Console: ", str)

		input.Text = ""
		input.Refresh()

		listener.ConsoleWriterInstance.WriteToConsole([]byte(str))
	}

	con := container.New(layout.NewVBoxLayout(), loginContainer, mode, sep, consoleScroll, input)

	mainWindow.SetContent(con)

	// add systray icon on desktop system;
	if desk, ok := ecApp.(desktop.App); ok {
		m := fyne.NewMenu(AppLabel,
			fyne.NewMenuItem("Show", func() {
				mainWindow.Show()
			}))
		if !fyne.CurrentDevice().IsMobile() {
			desk.SetSystemTrayMenu(m)
		}
		mainWindow.SetCloseIntercept(func() {
			dialog.ShowConfirm("Confirmation", config.InfoExitTip, func(option bool) {
				if option {
					confirmation.Close()
					mainWindow.Close()
					ecApp.Quit()
				}

				confirmation.Hide()
			}, confirmation)

			dialog.ShowConfirm("Confirmation", config.InfoTrayTip, func(option bool) {
				if option {
					hide := func() {
						<-time.After(200 * time.Millisecond)

						confirmation.Hide()

						mainWindow.Hide()
					}

					go hide()
				}
			}, confirmation)

			confirmation.Show()
		})
	}

	log.Print("Gui successfully initialized.")

	mainWindow.Show()
	mainWindow.SetFixedSize(true)
	mainWindow.SetMaster()

	ecApp.Run()
}
