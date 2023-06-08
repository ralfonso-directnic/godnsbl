/*
Package godnsbl lets you perform RBL (Real-time Blackhole List - https://en.wikipedia.org/wiki/DNSBL)
lookups using Golang

JSON annotations on the types are provided as a convenience.
*/
package godnsbl

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

/*
Blacklists is the list of blackhole lists to check against
*/
var skip []string

var Blacklists = []string{
	"xbl.spamhaus.org",
	"sbl.spamhaus.org",
	"zen.spamhaus.org",
	"pbl.spamhaus.org",
	"aspews.ext.sorbs.net",
	"b.barracudacentral.org",
	"bl.deadbeef.com",
	"bl.emailbasura.org",
	"bl.spamcannibal.org",
	"bl.spamcop.net",
	"blackholes.five-ten-sg.com",
	"blacklist.woody.ch",
	"bogons.cymru.com",
	"cbl.abuseat.org",
	"cdl.anti-spam.org.cn",
	"combined.abuse.ch",
	"combined.rbl.msrbl.net",
	"db.wpbl.info",
	"dnsbl-1.uceprotect.net",
	"dnsbl-2.uceprotect.net",
	"dnsbl-3.uceprotect.net",
	"dnsbl.cyberlogic.net",
	"dnsbl.dronebl.org",
	"dnsbl.inps.de",
	"dnsbl.njabl.org",
	"dnsbl.sorbs.net",
	"drone.abuse.ch",
	"duinv.aupads.org",
	"dul.dnsbl.sorbs.net",
	"dul.ru",
	"dyna.spamrats.com",
	"dynip.rothen.com",
	"http.dnsbl.sorbs.net",
	"images.rbl.msrbl.net",
	"ips.backscatterer.org",
	"ix.dnsbl.manitu.net",
	"korea.services.net",
	"misc.dnsbl.sorbs.net",
	"noptr.spamrats.com",
	"ohps.dnsbl.net.au",
	"omrs.dnsbl.net.au",
	"orvedb.aupads.org",
	"osps.dnsbl.net.au",
	"osrs.dnsbl.net.au",
	"owfs.dnsbl.net.au",
	"owps.dnsbl.net.au",
	"phishing.rbl.msrbl.net",
	"probes.dnsbl.net.au",
	"proxy.bl.gweep.ca",
	"proxy.block.transip.nl",
	"psbl.surriel.com",
	"rdts.dnsbl.net.au",
	"relays.bl.gweep.ca",
	"relays.bl.kundenserver.de",
	"relays.nether.net",
	"residential.block.transip.nl",
	"ricn.dnsbl.net.au",
	"rmst.dnsbl.net.au",
	"short.rbl.jp",
	"smtp.dnsbl.sorbs.net",
	"socks.dnsbl.sorbs.net",
	"spam.abuse.ch",
	"spam.dnsbl.sorbs.net",
	"spam.rbl.msrbl.net",
	"spam.spamrats.com",
	"spamlist.or.kr",
	"spamrbl.imp.ch",
	"t3direct.dnsbl.net.au",
	"tor.dnsbl.sectoor.de",
	"torserver.tor.dnsbl.sectoor.de",
	"ubl.lashback.com",
	"ubl.unsubscore.com",
	"virbl.bit.nl",
	"virus.rbl.jp",
	"virus.rbl.msrbl.net",
	"web.dnsbl.sorbs.net",
	"wormrbl.imp.ch",
	"zombie.dnsbl.sorbs.net"}

/*
RBLResults holds the results of the lookup.
*/
type RBLResults struct {
	// List is the RBL that was searched
	List string `json:"list"`
	// Host is the host or IP that was passed (i.e. smtp.gmail.com)
	Host string `json:"host"`
	// Results is a slice of Results - one per IP address searched
	Results []Result `json:"results"`
}

/*
Result holds the individual IP lookup results for each RBL search
*/
type Result struct {
	//rbl domain
	Rbl string `json:"rbl"`
	// Address is the IP address that was searched
	Address string `json:"address"`
	// Listed indicates whether or not the IP was on the RBL
	Listed bool `json:"listed"`
	// RBL lists sometimes add extra information as a TXT record
	// if any info is present, it will be stored here.
	Text string `json:"text"`
	// Error represents any error that was encountered (DNS timeout, host not
	// found, etc.) if any
	Error bool `json:"error"`
	// ErrorType is the type of error encountered if any
	ErrorType error `json:"error_type"`
}

/*
Reverse the octets of a given IPv4 address
64.233.171.108 becomes 108.171.233.64
*/

func SkipList(skip_src []string) {

	skip = skip_src

}

func Reverse(ip net.IP) string {
	if ip.To4() == nil {
		return ""
	}

	splitAddress := strings.Split(ip.String(), ".")

	for i, j := 0, len(splitAddress)-1; i < len(splitAddress)/2; i, j = i+1, j-1 {
		splitAddress[i], splitAddress[j] = splitAddress[j], splitAddress[i]
	}

	return strings.Join(splitAddress, ".")
}

func query(rbl string, host string, r *Result) {
	r.Listed = false
	r.Rbl = rbl

	lookup := fmt.Sprintf("%s.%s", host, rbl)

	res, err := net.LookupHost(lookup)
	if len(res) > 0 {

		for _, ip := range res {
			m, _ := regexp.MatchString("^127.0.0.*", ip)

			if m == true {
				r.Listed = true
			}
		}

		txt, _ := net.LookupTXT(lookup)
		if len(txt) > 0 {
			r.Text = txt[0]
		}
	}
	if err != nil {
		r.Error = true
		r.ErrorType = err
	}

	return
}

/*
Lookup performs the search and returns the RBLResults
*/
func Lookup(rblList string, targetHost string) RBLResults {
	r := RBLResults{}
	r.List = rblList
	r.Host = targetHost

	if ip, err := net.LookupIP(targetHost); err == nil {

		for _, addr := range ip {
			if addr.To4() != nil {
				res := Result{}
				res.Address = addr.String()

				addr := Reverse(addr)

				query(rblList, addr, &res)

				if len(res.Rbl) > 0 {

					r.Results = append(r.Results, res)

				}
			}
		}

	}
	return r
}

/*
ip: ip to lookup
threshold: the limit of entries that are listed to stop on, ie if 1 the first found will stop looking and return
dur: Timeout period to abort looking
*/

func BulkLookup(ip string, threshold int, dur time.Duration) []Result {

	wg := &sync.WaitGroup{}
	lookupResult := make(chan Result,len(Blacklists))
	var results []Result
	timeLimit := make(chan bool,2)
	finished := make(chan bool,2)

	//handle a duration if it's greater than default (0)
	if dur > 0 {
		go func() {
			select {
			case <-time.After(dur):
				timeLimit <- true
			}
		}()
	}

	for i, source := range Blacklists {

		if inSlice(skip, source) {
			continue // skip a list
		}

		wg.Add(1)
		go func(i int, source string) {
			defer wg.Done()
			rbl := Lookup(source, ip)
			for _, rb := range rbl.Results {
				if len(rb.Rbl) > 0 {
					select {
					case lookupResult <- rb:
						break
					case <-time.After(500 * time.Millisecond):

					}
				}
			}
		}(i, source)
	}

	var tctr int

	go func(){
		wg.Wait()
		select {
		case finished <- true:
			break
		case <-time.After(500 * time.Millisecond):

		}
	}()

	for {
		select {
		//ensures we always die if there is some odd issue witha  hang
		case <-time.After(60 * time.Second):
			return results
		case res := <-lookupResult:
			if res.Listed == true {
				tctr++
			}
			if len(res.Rbl) > 0 {
				results = append(results, res)
			}
			if tctr>threshold {
				return results
			}
		case <-finished:
			return results
		case <-timeLimit:
			return results
		}
	}
}

func inSlice(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
