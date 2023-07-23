package parser

import (
	"EasierConnect/core/config"
	"EasierConnect/core/structs"
	"github.com/dlclark/regexp2"
	"log"
	"net"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var domainRegExp *regexp.Regexp = regexp.MustCompile("(?:\\w+\\.)+\\w+")

func processSingleIpRule(rule, port string, waitChan *chan int) {
	minValue := port
	maxValue := port

	if strings.Contains(port, "~") {
		minValue = strings.Split(port, "~")[0]
		maxValue = strings.Split(port, "~")[1]
	}

	minValueInt, err := strconv.Atoi(minValue)
	if err != nil {
		log.Printf("Cannot parse port value from string")
		return
	}

	maxValueInt, err := strconv.Atoi(maxValue)
	if err != nil {
		log.Printf("Cannot parse port value from string")
		return
	}

	portRange := []int{minValueInt, maxValueInt}

	if strings.Contains(rule, "~") { // ip range 1.1.1.7~1.1.7.9
		IP := make([][]byte, 2)
		IP[0] = net.ParseIP(strings.Split(rule, "~")[0])
		IP[1] = net.ParseIP(strings.Split(rule, "~")[1])

		config.AppendSingleIpv4RangeRule(rule, IP, portRange)
	} else { // http://domain.example.com/path/to&something=good#extra

		// 第一次添加是解决URL限制到某个具体的路径
		config.AppendSingleDomainRule(rule, portRange)

		if domainRegExp == nil {
			domainRegExp, _ = regexp.Compile("(?:\\w+\\.)+\\w+")
		}

		pureDomain := domainRegExp.FindString(rule)

		// 第二次添加是解决Socks无法像Http代理那样获取到具体的路径
		// 只能将完整的域名添加进规则中
		config.AppendSingleDomainRule(pureDomain, portRange)
	}

	*waitChan <- 1
}

func processDnsData(dnsData string, debug bool) {
	for _, ent := range strings.Split(dnsData, ";") {
		dnsEntry := strings.Split(ent, ":")

		if len(dnsEntry) >= 3 {
			//RcID := dnsEntry[0]
			domain := dnsEntry[1]
			ip := dnsEntry[2]

			if domain != "" && ip != "" {
				config.AppendSingleDnsRule(domain, ip, debug)
			}
		}
	}
}

func processRcsData(rcsData structs.Resource, waitChan *chan int, cpuNumber *int) {
	RcsLen := len(rcsData.Rcs.Rc)
	for RcsIndex, ent := range rcsData.Rcs.Rc {
		if ent.Host == "" || ent.Port == "" {
			log.Printf("Found null entry when processing RcsData: [%s] %s %s", ent.Name, ent.Host, ent.Port)
			continue
		}

		domains := strings.Split(ent.Host, ";")
		ports := strings.Split(ent.Port, ";")

		if len(domains) >= 1 && len(ports) >= 1 {
			for index, domain := range domains {
				portRange := ports[index]

				if *cpuNumber > 0 {
					*cpuNumber--
				} else {
					<-*waitChan
				}
				processSingleIpRule(domain, portRange, waitChan)
			}
		}

		progress := int(float32(RcsIndex) / float32(RcsLen) * 100)

		if progress%20 == 0 {
			log.Printf("Progress: %v/100 (ResourceList.Rcs)", progress)
		}
	}
}

func ParseResourceLists(host, twfID string, debug bool) {
	ResourceList := structs.Resource{}
	res, ok := ParseXml(&ResourceList, host, config.PathRlist, twfID)

	cpuNumber := runtime.NumCPU()
	waitChan := make(chan int, cpuNumber)

	if !ok || ResourceList.Rcs.Rc == nil || len(ResourceList.Rcs.Rc) <= 0 || ResourceList.Dns.Data == "" {
		if res != "" {
			log.Printf("try parsing by regexp")

			escapeReplacementMap := map[string]string{
				"&nbsp;": string(rune(160)),
				"&amp;":  "&",
				"&quot;": `"`,
				"&lt;":   "<",
				"&gt;":   ">",
			}

			for from, to := range escapeReplacementMap {
				res = strings.ReplaceAll(res, from, to)
			}

			resUrlDecodedValue, err := url.QueryUnescape(res)
			if err != nil {
				log.Printf("Cannot do UrlDecode")
				return
			}

			ResourceListRegexp := regexp2.MustCompile("(?<=\" host=\").*?(?=\" enable_disguise=)", 0)
			ResourceListMatches, _ := ResourceListRegexp.FindStringMatch(resUrlDecodedValue)
			for ; ResourceListMatches != nil; ResourceListMatches, _ = ResourceListRegexp.FindNextMatch(ResourceListMatches) {
				if debug {
					log.Printf("ResourceListMatch -> " + ResourceListMatches.String() + "\n")
				}

				ResourceListData := ResourceListMatches.String()

				ResourceListDataHost := strings.Split(ResourceListData, `" port="`)[0]
				ResourceListDataPort := strings.Split(ResourceListData, `" port="`)[1]

				entry := structs.RcData{Host: ResourceListDataHost, Port: ResourceListDataPort}
				ResourceList.Rcs.Rc = append(ResourceList.Rcs.Rc, entry)
			}

			processRcsData(ResourceList, &waitChan, &cpuNumber)

			log.Printf("Parsed %v Domain rules", config.GetDomainRuleLen())
			log.Printf("Parsed %v Ipv4 rules", config.GetIpv4RuleLen())

			DnsDataRegexp := regexp2.MustCompile("(?<=<Dns dnsserver=\"\" data=\")[0-9A-Za-z:;.-]*?(?=\")", 0)
			DnsDataRegexpMatches, _ := DnsDataRegexp.FindStringMatch(resUrlDecodedValue)

			processDnsData(DnsDataRegexpMatches.String(), debug)

			log.Printf("Parsed %v Dns rules", config.GetDnsRuleLen())
		}
	} else {
		log.Printf("try parsing by goXml")

		processRcsData(ResourceList, &waitChan, &cpuNumber)

		log.Printf("Parsed %v Domain rules", config.GetDomainRuleLen())
		log.Printf("Parsed %v Ipv4 rules", config.GetIpv4RuleLen())

		processDnsData(ResourceList.Dns.Data, debug)

		log.Printf("Parsed %v Dns rules", config.GetDnsRuleLen())
	}
}

func ParseConfLists(host, twfID string, debug bool) {
	conf := structs.Conf{}
	_, _ = ParseXml(&conf, host, config.PathConf, twfID)
}
