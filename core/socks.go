package core

import (
	"EasierConnect/core/tool"
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"

	"EasierConnect/core/config"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/socks5"
)

func ServeSocks5(ipStack *stack.Stack, selfIp []byte, bindAddr string) {
	server := socks5.Server{
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {

			log.Printf("socks dial: %s", addr)

			parts := strings.Split(addr, ":")
			ip := parts[0]
			port := parts[1]

			portNum, err := strconv.Atoi(port)
			if err != nil {
				return nil, errors.New("invalid port: " + port)
			}

			if shouldIProxy, targetIP := shouldProxy(ip, portNum); shouldIProxy {
				if network != "tcp" {
					return nil, errors.New("only support tcp")
				}

				addrTarget := tcpip.FullAddress{
					NIC:  defaultNIC,
					Port: uint16(portNum),
					Addr: tcpip.Address(targetIP),
				}

				bind := tcpip.FullAddress{
					NIC:  defaultNIC,
					Addr: tcpip.Address(selfIp),
				}

				return gonet.DialTCPWithBind(context.Background(), ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
			}
			goDialer := &net.Dialer{}
			goDial := goDialer.DialContext

			return goDial(ctx, network, addr)
		},
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		panic("socks listen failed: " + err.Error())
	}

	log.Printf(">>>SOCKS5 SERVER listening on<<<: " + bindAddr)

	err = server.Serve(listener)
	panic(err)
}

func shouldProxy(ip string, port int) (shouldProxy bool, targetIP net.IP) {
	var allowedPorts = []int{1, 65535} // [0] -> Min, [1] -> Max

	originDomain := strings.Clone(ip)

	// 通过rlist 提供的固定解析列表返回地址
	// 通过域内 DNS 解析暂未实现
	if config.IsDnsRuleAvailable() {
		if customDnsRules, hasDnsRule := config.GetSingleDnsRule(ip); hasDnsRule {
			ip = customDnsRules
		}
	}

	target, err := net.ResolveIPAddr("ip", ip)
	targetIP = target.IP

	if err != nil {
		log.Printf(err.Error())
		return false, nil
	}

	if config.IsDomainRuleAvailable() {
		if allowAllWebSitesPorts, allowAllWebSites := config.GetSingleDomainRule("*"); allowAllWebSites {
			if allowAllWebSitesPorts[0] > 0 && allowAllWebSitesPorts[1] > 0 {
				allowedPorts[0] = tool.Min(allowedPorts[0], allowAllWebSitesPorts[0])
				allowedPorts[1] = tool.Max(allowedPorts[1], allowAllWebSitesPorts[1])

				if shouldProxy = port >= allowAllWebSitesPorts[0] && port <= allowAllWebSitesPorts[1]; shouldProxy {
					log.Printf("[Addr: %s, Resolvd: %v, AllowedPorts: %v, Rule: allowAllWebSites]", originDomain, ip, allowedPorts)
					return shouldProxy, targetIP
				}
			}
		}

		if allowedPorts, shouldProxy = config.GetSingleDomainRule(originDomain); shouldProxy && port >= allowedPorts[0] && port <= allowedPorts[1] {
			log.Printf("[Addr: %s, Resolvd: %v, AllowedPorts: %v, Rule: DomainName]", originDomain, ip, allowedPorts)
			return shouldProxy, targetIP
		}

		if allowedPorts, shouldProxy = config.GetSingleDomainRule(target.IP.String()); shouldProxy && port >= allowedPorts[0] && port <= allowedPorts[1] {
			log.Printf("[Addr: %s, Resolvd: %v, AllowedPorts: %v, Rule: ResolvedIP]", originDomain, ip, allowedPorts)
			return shouldProxy, targetIP
		}
	}

	if config.IsIpv4RuleAvailable() {
		for _, rule := range *config.GetIpv4Rules() {
			ipFrom := rule.IP[0]
			ipTo := rule.IP[1]

			if shouldProxy = bytes.Compare(target.IP, ipFrom) >= 0 && bytes.Compare(target.IP, ipTo) <= 0 &&
				port >= rule.Ports[0] &&
				port <= rule.Ports[1]; shouldProxy {
				log.Printf("[Addr: %s, Resolvd: %v, AllowedPorts: %v, Rule: IPV4 range]", originDomain, ip, rule.Ports)
				return shouldProxy, targetIP
			}
		}
	}

	log.Printf("[Addr: %s, Rule: skip]", ip)

	return
}
