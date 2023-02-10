package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"EasierConnect/core/config"

	txSocks5 "github.com/txthinking/socks5"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var (
	ipStack  *stack.Stack
	selfIp   []byte
	bindAddr string
)

type DefaultHandle struct {
	myResolverMain *net.Resolver
	myResolverBak  *net.Resolver
}

// UDPExchange used to store client address and remote connection
type UDPExchange struct {
	ClientAddr *net.UDPAddr
	RemoteConn *net.Conn
}

func (h *DefaultHandle) resolveDns(network string, domain string) (net.IP, error) {
	var hasDnsRule bool
	if config.IsDnsRuleAvailable() {
		var dnsRules string
		dnsRules, hasDnsRule = config.GetSingleDnsRule(domain)

		if hasDnsRule {
			return net.ParseIP(dnsRules), nil
		}
	}

	if h.myResolverMain == nil {
		h.myResolverMain = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				addrTarget := tcpip.FullAddress{
					NIC:  defaultNIC,
					Port: uint16(53),
					Addr: tcpip.Address(net.ParseIP(config.GetDnsServer()[0])),
				}

				if network == "tcp" {
					return gonet.DialTCP(ipStack, addrTarget, header.IPv4ProtocolNumber)
				} else if network == "udp" {
					return gonet.DialUDP(ipStack, nil, &addrTarget, header.IPv4ProtocolNumber)
				}

				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, "223.5.5.5:53")
			},
		}
	}

	if h.myResolverBak == nil {
		h.myResolverBak = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				addrTarget := tcpip.FullAddress{
					NIC:  defaultNIC,
					Port: uint16(53),
					Addr: tcpip.Address(net.ParseIP(config.GetDnsServer()[1])),
				}

				if network == "tcp" {
					return gonet.DialTCP(ipStack, addrTarget, header.IPv4ProtocolNumber)
				} else if network == "udp" {
					return gonet.DialUDP(ipStack, nil, &addrTarget, header.IPv4ProtocolNumber)
				}

				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, "223.5.5.5:53")
			},
		}
	}

	if len(config.GetDnsServer()) >= 1 && config.GetDnsServer()[0] != "0.0.0.0" {
		ip, err := h.myResolverMain.LookupIP(context.Background(), "ip4", domain)
		if err == nil {
			log.Printf("Using custom dns server: %s Resolved: %s. ", config.GetDnsServer()[0], ip)
			return ip[0], nil
		}
	}

	if len(config.GetDnsServer()) >= 2 && config.GetDnsServer()[1] != "0.0.0.0" {
		ip, err := h.myResolverMain.LookupIP(context.Background(), "ip4", domain)
		if err == nil {
			log.Printf("Using custom dns server: %s Resolved: %s. ", config.GetDnsServer()[0], ip)
			return ip[0], nil
		}
	}

	// I think only ipv4 is supported.
	result, err := net.ResolveIPAddr("ip4", domain)

	if err == nil {
		return result.IP, nil
	} else {
		return nil, err
	}
}

func (h *DefaultHandle) shouldProxy(domain string, port int) bool {
	var allowedPorts = []int{1, 65535} // [0] -> Min, [1] -> Max
	var useL3transport = true
	//	var hasDnsRule = false

	var doProxy = false

	if config.IsDomainRuleAvailable() {
		allowedPorts, useL3transport = config.GetSingleDomainRule(domain)
	}

	if !useL3transport && config.IsIpv4RuleAvailable() && net.ParseIP(domain) != nil {
		ip := net.ParseIP(domain)
		if DebugDump {
			log.Printf("Ipv4Rule is available ")
		}
		for _, rule := range *config.GetIpv4Rules() {
			if rule.CIDR {
				_, cidr, _ := net.ParseCIDR(rule.Rule)
				if DebugDump {
					log.Printf("Cidr test: %s %s %v", ip, rule.Rule, cidr.Contains(ip))
				}

				if cidr.Contains(ip) {
					if DebugDump {
						log.Printf("Cidr matched: %s %s", ip, rule.Rule)
					}

					useL3transport = true
					allowedPorts = rule.Ports
				}
			} else {
				if DebugDump {
					log.Printf("raw match test: %s %s", ip, rule.Rule)
				}

				ip1 := net.ParseIP(strings.Split(rule.Rule, "~")[0])
				ip2 := net.ParseIP(strings.Split(rule.Rule, "~")[1])

				if bytes.Compare(ip, ip1) >= 0 && bytes.Compare(ip, ip2) <= 0 {
					if DebugDump {
						log.Printf("raw matched: %s %s", ip1, ip2)
					}

					useL3transport = true
					allowedPorts = rule.Ports
				}
			}
		}
	}

	// 泛域全网资源
	if config.IsDomainRuleAvailable() {
		allowAllWebSitesPorts, allowAllWebSites := config.GetSingleDomainRule("*")

		if allowAllWebSites {
			if allowAllWebSitesPorts[0] > 0 && allowAllWebSitesPorts[1] > 0 {
				allowedPorts[0] = int(math.Min(float64(allowedPorts[0]), float64(allowAllWebSitesPorts[0])))
				allowedPorts[1] = int(math.Max(float64(allowedPorts[1]), float64(allowAllWebSitesPorts[1])))

				useL3transport = true
			}
		}
	}

	log.Printf("Addr: %s:%v, AllowedPorts: %v, useL3transport: %v", domain, port, allowedPorts, useL3transport)

	if /*(!useL3transport && hasDnsRule) || */ useL3transport && port >= allowedPorts[0] && port <= allowedPorts[1] {
		doProxy = true
	}

	return doProxy
}

func (h *DefaultHandle) myDialer(network string, laddr *net.UDPAddr, addr string) (net.Conn, error) {

	log.Printf("socks dial: %s", addr)

	parts := strings.Split(addr, ":")

	domain := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, errors.New("invalid port: " + parts[1])
	}

	dnsResult, err := h.resolveDns(network, domain)

	doProxy := h.shouldProxy(domain, port) || h.shouldProxy(dnsResult.String(), port)

	if err == nil && doProxy {
		addrTarget := tcpip.FullAddress{
			NIC:  defaultNIC,
			Port: uint16(port),
			Addr: tcpip.Address(dnsResult),
		}

		if network == "udp" {
			var bind *tcpip.FullAddress

			if laddr != nil {
				bind = &tcpip.FullAddress{
					NIC:  defaultNIC,
					Port: uint16(laddr.Port),
					Addr: tcpip.Address(laddr.IP),
				}
			}
			return gonet.DialUDP(ipStack, bind, &addrTarget, header.IPv4ProtocolNumber)
		} else {
			bind := tcpip.FullAddress{
				NIC:  defaultNIC,
				Addr: tcpip.Address(selfIp),
			}

			return gonet.DialTCPWithBind(context.Background(), ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
		}
	}

	log.Printf("skip: %s", addr)

	if network == "udp" {
		udpAddr, err0 := net.ResolveUDPAddr(network, addr)
		if err0 == nil {
			return net.DialUDP(network, laddr, udpAddr)
		} else {
			return nil, err0
		}
	} else {
		return net.Dial(network, addr)
	}
}

func (h *DefaultHandle) ConnectTcp(r *txSocks5.Request, w io.Writer) (net.Conn, error) {
	if txSocks5.Debug {
		log.Println("Call:", r.Address())
	}
	rc, err := h.myDialer("tcp", nil, r.Address())
	if err != nil {
		var p *txSocks5.Reply
		if r.Atyp == txSocks5.ATYPIPv4 || r.Atyp == txSocks5.ATYPDomain {
			p = txSocks5.NewReply(txSocks5.RepHostUnreachable, txSocks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = txSocks5.NewReply(txSocks5.RepHostUnreachable, txSocks5.ATYPIPv6, net.IPv6zero, []byte{0x00, 0x00})
		}
		if _, err = p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}

	a, addr, port, err := txSocks5.ParseAddress(rc.LocalAddr().String())
	if err != nil {
		var p *txSocks5.Reply
		if r.Atyp == txSocks5.ATYPIPv4 || r.Atyp == txSocks5.ATYPDomain {
			p = txSocks5.NewReply(txSocks5.RepHostUnreachable, txSocks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else {
			p = txSocks5.NewReply(txSocks5.RepHostUnreachable, txSocks5.ATYPIPv6, net.IPv6zero, []byte{0x00, 0x00})
		}
		if _, err = p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}
	if a == txSocks5.ATYPDomain {
		addr = addr[1:]
	}
	p := txSocks5.NewReply(txSocks5.RepSuccess, a, addr, port)
	if _, err = p.WriteTo(w); err != nil {
		return nil, err
	}

	return rc, nil
}

// TCPHandle auto handle request. You may prefer to do yourself.
func (h *DefaultHandle) TCPHandle(s *txSocks5.Server, c *net.TCPConn, r *txSocks5.Request) error {
	if r.Cmd == txSocks5.CmdConnect {
		rc, err := h.ConnectTcp(r, c)
		if err != nil {
			return err
		}
		defer func(rc net.Conn) {
			_ = rc.Close()
		}(rc)
		go func() {
			var bf [1024 * 2]byte
			for {
				if rc == nil {
					return
				}
				if s.TCPTimeout != 0 {
					if err = rc.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
						return
					}
				}
				i, err0 := rc.Read(bf[:])
				if err0 != nil {
					return
				}
				if _, err = c.Write(bf[0:i]); err != nil {
					return
				}
			}
		}()
		var bf [1024 * 2]byte
		for {
			if c == nil {
				break
			}
			if s.TCPTimeout != 0 {
				if err = c.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
					return nil
				}
			}
			i, err0 := c.Read(bf[:])
			if err0 != nil {
				return nil
			}
			if _, err = rc.Write(bf[0:i]); err != nil {
				return nil
			}
		}
	}
	if r.Cmd == txSocks5.CmdUDP {
		caddr, err := r.UDP(c, s.ServerAddr)
		if err != nil {
			return err
		}
		ch := make(chan byte)
		defer close(ch)
		s.AssociatedUDP.Set(caddr.String(), ch, -1)
		defer s.AssociatedUDP.Delete(caddr.String())
		io.Copy(io.Discard, c)
		if txSocks5.Debug {
			log.Printf("A tcp connection that udp %#v associated closed\n", caddr.String())
		}
		return nil
	}
	return txSocks5.ErrUnsupportCmd
}

// UDPHandle auto handle packet. You may prefer to do yourself.
func (h *DefaultHandle) UDPHandle(s *txSocks5.Server, addr *net.UDPAddr, d *txSocks5.Datagram) error {
	src := addr.String()
	var ch chan byte
	if s.LimitUDP {
		any11, ok := s.AssociatedUDP.Get(src)
		if !ok {
			return fmt.Errorf("this udp address %s is not associated with tcp", src)
		}
		ch = any11.(chan byte)
	}
	send := func(ue *UDPExchange, data []byte) error {
		select {
		case <-ch:
			return fmt.Errorf("this udp address %s is not associated with tcp", src)
		default:
			_, err := (*ue.RemoteConn).Write(data)
			if err != nil {
				return err
			}
			if txSocks5.Debug {
				log.Printf("Sent UDP data to remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), (*ue.RemoteConn).LocalAddr().String(), (*ue.RemoteConn).RemoteAddr().String(), data)
			}
		}
		return nil
	}

	dst := d.Address()
	var ue *UDPExchange
	iue, ok := s.UDPExchanges.Get(src + dst)
	if ok {
		ue = iue.(*UDPExchange)
		return send(ue, d.Data)
	}

	if txSocks5.Debug {
		log.Printf("Call udp: %#v\n", dst)
	}
	var laddr *net.UDPAddr
	any11, ok := s.UDPSrc.Get(src + dst)
	if ok {
		laddr = any11.(*net.UDPAddr)
	}
	rc, err := h.myDialer("udp", laddr, dst)
	if err != nil {
		if !strings.Contains(err.Error(), "address already in use") {
			return err
		}
		rc, err = h.myDialer("udp", nil, dst)
		if err != nil {
			return err
		}
		laddr = nil
	}
	if rc == nil {
		return err
	}
	if laddr == nil {
		s.UDPSrc.Set(src+dst, rc.LocalAddr().(*net.UDPAddr), -1)
	}
	ue = &UDPExchange{
		ClientAddr: addr,
		RemoteConn: &rc,
	}
	if txSocks5.Debug {
		log.Printf("Created remote UDP conn for client. client: %#v server: %#v remote: %#v\n", addr.String(), (*ue.RemoteConn).LocalAddr().String(), d.Address())
	}
	if err = send(ue, d.Data); err != nil {
		(*ue.RemoteConn).Close()
		return err
	}
	s.UDPExchanges.Set(src+dst, ue, -1)
	go func(ue *UDPExchange, dst string) {
		defer func() {
			(*ue.RemoteConn).Close()
			s.UDPExchanges.Delete(ue.ClientAddr.String() + dst)
		}()
		var b [65507]byte
		for {
			select {
			case <-ch:
				if txSocks5.Debug {
					log.Printf("The tcp that udp address %s associated closed\n", ue.ClientAddr.String())
				}
				return
			default:
				if s.UDPTimeout != 0 {
					if err = (*ue.RemoteConn).SetDeadline(time.Now().Add(time.Duration(s.UDPTimeout) * time.Second)); err != nil {
						log.Println(err)
						return
					}
				}
				n, err0 := (*ue.RemoteConn).Read(b[:])
				if err0 != nil {
					return
				}
				if txSocks5.Debug {
					log.Printf("Got UDP data from remote. client: %#v server: %#v remote: %#v data: %#v\n", ue.ClientAddr.String(), (*ue.RemoteConn).LocalAddr().String(), (*ue.RemoteConn).RemoteAddr().String(), b[0:n])
				}
				a, addr1, port, err1 := txSocks5.ParseAddress(dst)
				if err1 != nil {
					log.Println(err1)
					return
				}
				if a == txSocks5.ATYPDomain {
					addr1 = addr1[1:]
				}
				d1 := txSocks5.NewDatagram(a, addr1, port, b[0:n])
				if _, err = s.UDPConn.WriteToUDP(d1.Bytes(), ue.ClientAddr); err != nil {
					return
				}
				if txSocks5.Debug {
					log.Printf("Sent Datagram. client: %#v server: %#v remote: %#v data: %#v %#v %#v %#v %#v %#v datagram address: %#v\n", ue.ClientAddr.String(), (*ue.RemoteConn).LocalAddr().String(), (*ue.RemoteConn).RemoteAddr().String(), d1.Rsv, d1.Frag, d1.Atyp, d1.DstAddr, d1.DstPort, d1.Data, d1.Address())
				}
			}
		}
	}(ue, dst)
	return nil
}

func ServeSocks5(ipStack_ *stack.Stack, selfIp_ []byte, bindAddr_ string) {
	ipStack = ipStack_
	selfIp = selfIp_
	bindAddr = bindAddr_

	txSocks5.Debug = true
	s, _ := txSocks5.NewClassicServer(SocksBind, "127.0.0.1", "", "", 5000, 5000)
	s.ListenAndServe(&DefaultHandle{})
}
