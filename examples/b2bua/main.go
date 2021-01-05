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
	"github.com/cloudwebrtc/go-sip-ua/pkg/registry"

	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/fcm"
	"github.com/cloudwebrtc/go-sip-ua/examples/b2bua/pushkit"
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
			prompt.OptionHistory([]string{"calls", "users", "onlines"}),
			prompt.OptionPrefixTextColor(prompt.Yellow),
			prompt.OptionPreviewSuggestionTextColor(prompt.Blue),
			prompt.OptionSelectedSuggestionBGColor(prompt.LightGray),
			prompt.OptionSuggestionBGColor(prompt.DarkGray))

		switch t {
		case "users":
			fallthrough
		case "ul":
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
		case "calls":
			fallthrough
		case "cl":
			calls := b2bua.Calls()
			if len(calls) > 0 {
				fmt.Printf("Calls:\n")
				for _, call := range calls {
					fmt.Printf("%v:\n", call.ToString())
				}
			} else {
				fmt.Printf("No active calls\n")
			}
		case "onlines":
			fallthrough
		case "rr":
			aors := b2bua.GetRegistry().GetAllContacts()
			if len(aors) > 0 {
				for aor, instances := range aors {
					fmt.Printf("AOR: %v:\n", aor)
					for _, instance := range instances {
						pn := ""
						//if instance.PNParams != nil {
						//	pn = fmt.Sprintf("\n\tPN-Params: %v", instance.PNParams.String())
						//}
						fmt.Printf("\t%v, Expires: %d, Source: %v, Transport: %v %v\n",
							(*instance).UserAgent,
							(*instance).RegExpires,
							(*instance).Source,
							(*instance).Transport,
							pn)
					}
				}
			} else {
				fmt.Printf("No online devices\n")
			}
		case "pnr":
			pnrs := b2bua.GetRFC8599().PNRecords()
			if len(pnrs) > 0 {
				fmt.Printf("PN Records:\n")
				for pn, aor := range pnrs {
					fmt.Printf("AOR: %v => pn-provider=%v, pn-param=%v, pn-prid=%v\n", aor, pn.Provider, pn.Param, pn.PRID)
				}
			} else {
				fmt.Printf("No online devices\n")
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

	pushCallback := func(pn *registry.PNParams, payload map[string]string) error {
		fmt.Printf("Handle Push Request:\nprovider=%v\nparam=%v\nprid=%v\npayload=%v", pn.Provider, pn.Param, pn.PRID, payload)
		switch pn.Provider {
		case "apns":
			pushkit.DoPushKit("./voip-callkeep.p12", pn.PRID, payload)
			return nil
		case "fcm":
			fcm.FCMPush("service-account.json", pn.PRID, payload)
			return nil
		}
		return fmt.Errorf("%v provider not found", pn.Provider)
	}

	b2bua := b2bua.NewB2BUA(pushCallback)

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
