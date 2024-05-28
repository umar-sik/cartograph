package vectorize

import (
	"errors"
	"net"
)

// ip.go contains the code to vectorize IP addresses.

// Ip converts the given IP address to a vector for machine learning analysis.
func Ip(ip net.IP) ([]float32, error) {
	// Convert IPv4 address to IPv6, if necessary
	ip.To16()
	if ip == nil {
		return nil, errors.New("invalid IP address")
	}

	// Create an integer slice with each decimal value in the IPv6 address
	decimalSlice := make([]float32, len(ip))
	for i, v := range ip {
		decimalSlice[i] = float32(int(v))
	}

	return decimalSlice, nil
}
