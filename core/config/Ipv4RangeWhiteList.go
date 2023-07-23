package config

var Ipv4RangeRules *[]Ipv4RangeRule

// Ipv4RangeRule Ipv4 rule with range
type Ipv4RangeRule struct {
	Rule  string
	IP    [][]byte
	Ports []int
}

func AppendSingleIpv4RangeRule(rule string, ip [][]byte, ports []int) {
	if Ipv4RangeRules == nil {
		Ipv4RangeRules = &[]Ipv4RangeRule{}
	}

	*Ipv4RangeRules = append(*Ipv4RangeRules, Ipv4RangeRule{Rule: rule, IP: ip, Ports: ports})
}

func GetIpv4Rules() *[]Ipv4RangeRule {
	return Ipv4RangeRules
}

func IsIpv4RuleAvailable() bool {
	return Ipv4RangeRules != nil
}

func GetIpv4RuleLen() int {
	if IsIpv4RuleAvailable() {
		return len(*Ipv4RangeRules)
	} else {
		return 0
	}
}
