package config

import (
	"github.com/cornelk/hashmap"
)

// domain[[]int {min, max}]
var domainRules *hashmap.Map[string, []int]

func AppendSingleDomainRule(domain string, ports []int) {
	if domainRules == nil {
		domainRules = hashmap.New[string, []int]()
	}

	domainRules.Set(domain, ports)
}

func GetSingleDomainRule(domain string) ([]int, bool) {
	return domainRules.Get(domain)
}

func IsDomainRuleAvailable() bool {
	return domainRules != nil
}

func GetDomainRuleLen() int {
	if IsDomainRuleAvailable() {
		return domainRules.Len()
	} else {
		return 0
	}
}
