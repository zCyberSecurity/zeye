package input

import (
	"encoding/xml"
	"io"
	"strings"
)

// nmap XML structure mirrors the output of `nmap -oX`.
type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   int       `xml:"portid,attr"`
	State    nmapState `xml:"state"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

// parseNmap reads nmap XML output (-oX) from r.
func parseNmap(r io.Reader, out chan<- ScanResult) {
	var run nmapRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return
	}

	for _, host := range run.Hosts {
		ip := ""
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}

		for _, p := range host.Ports.Ports {
			if strings.ToLower(p.State.State) != "open" {
				continue
			}
			out <- ScanResult{
				IP:    ip,
				Port:  uint16(p.PortID),
				Proto: normalizeProto(p.Protocol),
			}
		}
	}
}
