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
	"github.com/cloudwebrtc/go-sip-ua/pkg/b2bua"
)

func completer(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "users", Description: "Show sip accounts"},
		{Text: "onlines", Description: "Show online sip devices"},
		{Text: "calls", Description: "Show active calls"},
		{Text: "exit", Description: "Exit"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func usage() {
	fmt.Fprintf(os.Stderr, `go pbx version: go-pbx/1.10.0
Usage: server [-hc]

Options:
`)
	flag.PrintDefaults()
}

func consoleLoop(b2bua *b2bua.B2BUA) {

	fmt.Println("Please select command.")
	for {
		t := prompt.Input("CLI> ", completer,
			prompt.OptionTitle("GO B2BUA 1.0.0"),
			prompt.OptionHistory([]string{"users", "onlines", "exit"}),
			prompt.OptionPrefixTextColor(prompt.Yellow),
			prompt.OptionPreviewSuggestionTextColor(prompt.Blue),
			prompt.OptionSelectedSuggestionBGColor(prompt.LightGray),
			prompt.OptionSuggestionBGColor(prompt.DarkGray))

		switch t {
		case "users":
			accounts := b2bua.GetAccounts()
			if len(accounts) > 0 {
				fmt.Printf("Username \t Password\n")
				for user, pass := range accounts {
					fmt.Printf("%v \t\t %v\n", user, pass)
				}
			}
		case "onlines":
			aors := b2bua.GetRegistry().GetAllContacts()
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
		case "exit":
			fmt.Println("Exit now.")
			b2bua.Shutdown()
			return
		}
	}
}

func main() {
	console := false
	h := false
	flag.BoolVar(&h, "h", false, "this help")
	flag.BoolVar(&console, "c", false, "console mode")
	flag.Usage = usage

	flag.Parse()

	if h {
		flag.Usage()
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		fmt.Print("Start pprof on :6655\n")
		http.ListenAndServe(":6655", nil)
	}()

	b2bua := b2bua.NewB2BUA()

	// Add sample accounts.
	b2bua.AddAccount("100", "100")
	b2bua.AddAccount("200", "200")
	b2bua.AddAccount("300", "300")
	b2bua.AddAccount("400", "400")

	if console {
		consoleLoop(b2bua)
		return
	}

	<-stop
	b2bua.Shutdown()
}
