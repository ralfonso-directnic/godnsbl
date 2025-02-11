package main

import (
	"encoding/json"
	"fmt"
	"log"
    "time"
	"os"
    "flag"
	"github.com/ralfonso-directnic/godnsbl"
)

var thold int
var ip string
var dur string

func init(){
    flag.StringVar(&ip,"ip","","Ip or domain to search")
	flag.IntVar(&thold,"threshold",0,"The number of listed block lists before stopping lookups,0 for all")
	flag.StringVar(&dur,"tmout","","Golang duration string (5s, 50ms,etc)")
}

func main() {


	if len(os.Args)  < 2 {
		fmt.Println("Please supply a domain name or IP address.")
		os.Exit(1)
	}

    flag.Parse()

	pdur,pd := time.ParseDuration(dur)

	if pd != nil {

		pdur = time.Millisecond * 500

	}

    results := godnsbl.BulkLookup(ip,thold,pdur)


	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(&results); err != nil {
		log.Println(err)
	}

}
