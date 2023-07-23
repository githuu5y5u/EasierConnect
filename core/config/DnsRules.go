package config

import (
	"github.com/cornelk/hashmap"
)

// domain[ip]
var dnsRules *hashmap.Map[string, string]

func AppendSingleDnsRule(domain, ip string, debug bool) {
	if dnsRules == nil {
		dnsRules = hashmap.New[string, string]()
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
