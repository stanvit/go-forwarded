package forwarded

import (
	"net"
	"testing"
)

func TestIpnets(t *testing.T) {
	stringNets := "192.168.3.4,172.17.4.127/24 , 10.0.0.1/30, fe81::20f:75fa:fe1a:1af2/64,fe99::20f:75fa:fe1a:1af2"
	nets := new(IPNets)
	// test parsing
	if err := nets.Set(stringNets); err != nil {
		t.Fatal("Failed to parse networks from string: ", err)
	}
	if l := len(*nets); l != 5 {
		t.Fatal("The length of IPNets should be 5, not ", l)
	}
	// make 100% coverage by "testing" String()
	_ = nets.String()
	// test individual nets
	for i, proposed := range []string{"192.168.3.4/32", "172.17.4.0/24", "10.0.0.0/30", "fe81::/64", "fe99::20f:75fa:fe1a:1af2/128"} {
		if parsed := (*nets)[i].String(); parsed != proposed {
			t.Errorf("The element %d parsed as %v, but should be %v", i, parsed, proposed)
		}
	}
	// test networks matching
	for _, s := range []string{"192.168.3.4", "172.17.4.0", "172.17.4.128", "172.17.4.255", "10.0.0.1", "fe81::ff", "fe99::20f:75fa:fe1a:1af2"} {
		if ip := net.ParseIP(s); !nets.Contains(ip) {
			t.Errorf("%s should match the IPNets %v", ip, nets)
		}
	}
	// test not matching networks
	for _, s := range []string{"192.168.3.5", "172.17.3.255", "172.17.5.0", "10.0.0.4", "fe82::ff", "fe99::20f:75fa:fe1a:1af3"} {
		if ip := net.ParseIP(s); nets.Contains(ip) {
			t.Errorf("%s should not match the IPNets %v", ip, nets)
		}
	}
	// test ivalid CIDR:
	if err := nets.Set("10.0.0.0/99"); err == nil {
		t.Error("Should fail while parsing invalid CIDR 10.0.0.0/99")
	}
}
