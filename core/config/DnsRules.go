package config

import (
	"github.com/cornelk/hashmap"
	"log"
)

// domain[ip]
var dnsRules *hashmap.Map[string, string]
var dnsServers []string

func AppendSingleDnsRule(domain, ip string, debug bool) {
	if dnsRules == nil {
		dnsRules = hashmap.New[string, string]()
	}

	if debug {
		log.Printf("AppendSingleDnsRule: %s[%s]", domain, ip)
	}

	dnsRules.Set(domain, ip)
}

func GetSingleDnsRule(domain string) (string, bool) {
	return dnsRules.Get(domain)
}

func IsDnsRuleAvailable() bool {
	return dnsRules != nil
}

func GetDnsRuleLen() int {
	if IsDnsRuleAvailable() {
		return dnsRules.Len()
	} else {
		return 0
	}
}

func AppendDnsServer(ser ...string) {
	dnsServers = append(dnsServers, ser...)
}

func GetDnsServer() []string {
	return dnsServers
}
