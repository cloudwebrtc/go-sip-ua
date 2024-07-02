package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"github.com/c-bata/go-prompt"
	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/b2bua"
	"github.com/cloudwebrtc/go-sip-ua/pkg/utils"
	"github.com/ghettovoice/gosip/log"
)

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "users", Description: "Show sip accounts"},
		{Text: "onlines", Description: "Show online sip devices"},
		{Text: "calls", Description: "Show active calls"},
		{Text: "originate", Description: "Originate a call and bridge to another call"},
		{Text: "set debug on", Description: "Show debug msg in console"},
		{Text: "set debug off", Description: "Turn off debug msg in console"},
		{Text: "show loggers", Description: "Print Loggers"},
		{Text: "exit", Description: "Exit"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func usage() {
	fmt.Fprintf(os.Stderr, `go pbx version: go-pbx/1.10.0
Usage: server [-nc]

Options:
`)
	flag.PrintDefaults()
}

func consoleLoop(b2bua *b2bua.B2BUA) {

	usersCompleter := func(d prompt.Document) []prompt.Suggest {
		accounts := b2bua.GetAccounts()
		s := make([]prompt.Suggest, 0, len(accounts))
		for user := range accounts {
			s = append(s, prompt.Suggest{Text: user, Description: "User"})
		}
		aors := b2bua.GetRegistry().GetAllContacts()
		for aor := range aors {
			for _, instance := range aors[aor] {
				s = append(s, prompt.Suggest{Text: instance.Contact.Address.String(), Description: "online device"})
			}
		}
		return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
	}

	fmt.Println("Please select command.")
	for {
		t := prompt.Input("CLI> ", completer,
			prompt.OptionTitle("GO B2BUA 1.0.0"),
			prompt.OptionHistory([]string{"calls", "users", "onlines"}),
			prompt.OptionPrefixTextColor(prompt.Yellow),
			prompt.OptionPreviewSuggestionTextColor(prompt.Blue),
			prompt.OptionSelectedSuggestionBGColor(prompt.LightGray),
			prompt.OptionSuggestionBGColor(prompt.DarkGray))

		switch t {
		case "show loggers":
			loggers := utils.GetLoggers()
			for prefix, log := range loggers {
				fmt.Printf("%v => %v\n", prefix, log.Level())
			}
		case "set debug on":
			b2bua.SetLogLevel(log.DebugLevel)
			fmt.Printf("Set Log level to debug\n")
		case "set debug off":
			b2bua.SetLogLevel(log.InfoLevel)
			fmt.Printf("Set Log level to info\n")
		case "users":
			fallthrough
		case "ul": /* user list*/
			accounts := b2bua.GetAccounts()
			if len(accounts) > 0 {
				fmt.Printf("Users:\n")
				fmt.Printf("Username \t Password\n")
				for user, pass := range accounts {
					fmt.Printf("%v \t\t %v\n", user, pass)
				}
			} else {
				fmt.Printf("No users\n")
			}
		case "originate":
			fmt.Printf("Please enter the source user: ")
			source := prompt.Input("Source> ", usersCompleter)
			fmt.Printf("Please enter the destination user: ")
			destination := prompt.Input("Destination> ", usersCompleter)
			b2bua.Originate(source, destination)
		case "calls":
			fallthrough
		case "cl": /* call list*/
			bridges := b2bua.BridgedCalls()
			if len(bridges) > 0 {
				fmt.Printf("Bridged Calls:\n")
				for _, call := range bridges {
					fmt.Printf("%v\n", call.ToString())
				}
			} else {
				fmt.Printf("No active calls\n")
			}
		case "onlines":
			fallthrough
		case "rr": /* register records*/
			aors := b2bua.GetRegistry().GetAllContacts()
			if len(aors) > 0 {
				for aor, instances := range aors {
					fmt.Printf("AOR: %v:\n", aor)
					for _, instance := range instances {
						fmt.Printf("\t%v, Expires: %d, Source: %v, Transport: %v\n",
							(*instance).UserAgent,
							(*instance).RegExpires,
							(*instance).Source,
							(*instance).Transport)
					}
				}
			} else {
				fmt.Printf("No online devices\n")
			}
		case "pr": /* pn records*/
			pnrs := b2bua.GetRFC8599().PNRecords()
			if len(pnrs) > 0 {
				fmt.Printf("PN Records:\n")
				for pn, aor := range pnrs {
					fmt.Printf("AOR: %v => pn-provider=%v, pn-param=%v, pn-prid=%v\n", aor, pn.Provider, pn.Param, pn.PRID)
				}
			} else {
				fmt.Printf("No pn records\n")
			}
		case "exit":
			fmt.Println("Exit now.")
			b2bua.Shutdown()
			return
		}
	}
}

func main() {
	noconsole := false
	disableAuth := false
	enableTLS := false
	h := false
	flag.BoolVar(&h, "h", false, "this help")
	flag.BoolVar(&noconsole, "nc", false, "no console mode")
	flag.BoolVar(&disableAuth, "da", false, "disable auth mode")
	flag.BoolVar(&enableTLS, "tls", false, "enable TLS")
	flag.Usage = usage

	flag.Parse()

	if h {
		flag.Usage()
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		fmt.Print("Start pprof on :6658\n")
		http.ListenAndServe(":6658", nil)
	}()

	b2bua := b2bua.NewB2BUA(disableAuth, enableTLS)

	// Add sample accounts.
	b2bua.AddAccount("100", "100")
	b2bua.AddAccount("200", "200")
	b2bua.AddAccount("300", "300")
	b2bua.AddAccount("400", "400")

	if !noconsole {
		consoleLoop(b2bua)
		return
	}

	<-stop
	b2bua.Shutdown()
}
