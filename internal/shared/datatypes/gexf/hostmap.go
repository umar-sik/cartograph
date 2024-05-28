package gexf

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sync"
	"time"
)

// HostMapGexf is a Gexf file that contains a map of hosts and their connections to other hosts.
// It uses a dynamic graph with start times for each node and edge.
type HostMapGexf struct {
	mu        sync.RWMutex
	XMLName   xml.Name `xml:"gexf"`
	Xmlns     string   `xml:"xmlns,attr"`
	Xsi       string   `xml:"xmlns:xsi,attr"`
	SchemaLoc string   `xml:"xsi:schemaLocation,attr"`
	Version   string   `xml:"version,attr"`
	Meta      Meta
	Graph     HostMapGraph
}

type HostMapGraph struct {
	XMLName            xml.Name `xml:"graph"`
	Mode               string   `xml:"mode,attr"`
	TimeFormat         string   `xml:"timeformat,attr,omitempty"`
	TimeRepresentation string   `xml:"timerepresentation,attr,omitempty"`
	DefaultEdgeType    string   `xml:"defaultedgetype,attr,omitempty"`
	HostNodes          HostNodes
	HostEdges          HostEdges
}

// HostNodes contains a map of nodes, where the key is the node, and the value is a simple boolean to save space.
type HostNodes struct {
	XMLName xml.Name        `xml:"nodes"`
	Nodes   map[string]bool `xml:"node"`
	Count   int             `xml:"count,attr"`
}

// MarshalXML is a custom XML marshaller for HostNodes.
func (n HostNodes) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	// Add the outer nodes token
	start.Name = xml.Name{Local: "nodes"}
	start.Attr = []xml.Attr{
		{
			Name:  xml.Name{Local: "count"},
			Value: fmt.Sprintf("%d", n.Count),
		},
	}
	if err := e.EncodeToken(start); err != nil {
		return fmt.Errorf("unable to create nodes element: %w", err)
	}

	// Create the node start token, which will be used for all nodes
	nodeStart := xml.StartElement{
		Name: xml.Name{Local: "node"},
	}

	// Iterate through all the keys in the map.
	// The keys will be the nodes, and the values will be the start times.
	for k := range n.Nodes {
		// Create the node object
		node := Node{
			Id:    k,
			Label: k,
		}

		// Encode the node
		if err := e.EncodeElement(node, nodeStart); err != nil {
			return fmt.Errorf("unable to encode node: %w", err)
		}
	}

	// Close the outer nodes token
	if err := e.EncodeToken(start.End()); err != nil {
		return fmt.Errorf("unable to close nodes element: %w", err)
	}

	// Flush the encoder
	if err := e.Flush(); err != nil {
		return fmt.Errorf("unable to flush encoder: %w", err)
	}

	return nil
}

// HostEdges contains a map of edges, where the key is the source node, and the value is a map of target nodes
// to simple booleans (to save space).
type HostEdges struct {
	XMLName xml.Name                   `xml:"edges"`
	Edges   map[string]map[string]bool `xml:"edge"`
	Count   int                        `xml:"count,attr"`
}

// EdgeAttributes contains the attributes for an edge.
type EdgeAttributes struct {
	XMLName xml.Name `xml:"attvalues"`
	Values  []Value  `xml:"attvalue"`
}

// Value contains the value for an attribute.
type Value struct {
	XMLName xml.Name `xml:"attvalue"`
	For     string   `xml:"for,attr"`
	Value   string   `xml:"value,attr"`
}

// MarshalXML is a custom XML marshaller for HostEdges.
func (he HostEdges) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	// Add the outer edges token
	start.Name = xml.Name{Local: "edges"}
	start.Attr = []xml.Attr{
		{
			Name:  xml.Name{Local: "count"},
			Value: fmt.Sprintf("%d", he.Count),
		},
	}
	if err := e.EncodeToken(start); err != nil {
		return fmt.Errorf("unable to create edges element: %w", err)
	}

	// Create the edge start token, which will be used for all edges
	edgeStart := xml.StartElement{
		Name: xml.Name{Local: "edge"},
	}

	// Iterate through all the keys in the map.
	// The keys will be the source nodes, and the values will be a map of target nodes to start times.
	for source, targets := range he.Edges {
		// Iterate through all the keys in the target map.
		// The keys will be the target nodes, and the values will be the start times.
		for target := range targets {
			// Create the edge object
			edge := Edge{
				Id:     source + "-" + target,
				Source: source,
				Target: target,
			}

			// Encode the edge
			if err := e.EncodeElement(edge, edgeStart); err != nil {
				return fmt.Errorf("unable to encode edge: %w", err)
			}
		}
	}

	// Close the outer edges token
	if err := e.EncodeToken(start.End()); err != nil {
		return fmt.Errorf("unable to close edges element: %w", err)
	}

	// Flush the encoder
	if err := e.Flush(); err != nil {
		return fmt.Errorf("unable to flush encoder: %w", err)
	}

	return nil
}

// Write creates the XML for the Gexf struct and writes it to the provided writer.
// It returns the number of bytes written and any errors, conforming to the io.Writer interface.
func (g *HostMapGexf) Write(w io.Writer) (int, error) {
	// Set the nodes and edges counts before writing, to optimize the parser reads
	g.Graph.HostNodes.Count = len(g.Graph.HostNodes.Nodes)
	g.Graph.HostEdges.Count = 0
	for _, m := range g.Graph.HostEdges.Edges {
		g.Graph.HostEdges.Count += len(m)
	}

	// Create a buffer to hold the encoded XML data
	buf := new(bytes.Buffer)

	// Create the XML encoder
	e := xml.NewEncoder(buf)

	// Start with the XML processing instructions
	if err := e.EncodeToken(xml.ProcInst{"xml", []byte(`version="1.0" encoding="UTF-8"`)}); err != nil {
		return 0, fmt.Errorf("unable to encode XML processing instructions: %w", err)
	}

	// DEBUG: Add indentation
	// e.Indent("", "  ")

	// Encode the rest of the Gexf struct
	if err := e.Encode(g); err != nil {
		return 0, fmt.Errorf("unable to encode Gexf struct: %w", err)
	}

	// Write the XML data to the writer
	n, bufWriteErr := buf.WriteTo(w)
	if bufWriteErr != nil {
		return 0, fmt.Errorf("unable to write XML data to writer: %w", bufWriteErr)
	}

	return int(n), nil
}

// AddHost adds a host to the host map graph.
// If the host already exists, it will be updated with the earliest start time.
func (g *HostMapGexf) AddHost(host string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Add the host to the host map graph
	g.Graph.HostNodes.Nodes[host] = true
}

// AddConnection adds a connection (edge) to the host map graph.
// If the edge already exists, it will be updated with the earliest start time.
// If either of the hosts in the edge do not exist, they will be added to the host map graph.
func (g *HostMapGexf) AddConnection(sourceHost, targetHost string) {
	// Skip empty hosts
	if sourceHost == "" || targetHost == "" {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Add the source host to the host nodes map
	g.Graph.HostNodes.Nodes[sourceHost] = true

	// Add the target host to the host nodes map
	g.Graph.HostNodes.Nodes[targetHost] = true

	// Check for existing source host in the edges map
	if _, ok := g.Graph.HostEdges.Edges[sourceHost]; !ok {
		// Add the source host to the host map graph
		g.Graph.HostEdges.Edges[sourceHost] = make(map[string]bool)
	}

	// Add the target host to the source host
	g.Graph.HostEdges.Edges[sourceHost][targetHost] = true
}

// CreateHostMapGexf creates a new HostMapGexf struct.
func CreateHostMapGexf() *HostMapGexf {
	// Create the host map graph
	g := HostMapGexf{
		mu:        sync.RWMutex{},
		XMLName:   xml.Name{Local: "gexf"},
		Xmlns:     "http://gexf.net/1.3",
		Xsi:       "http://www.w3.org/2001/XMLSchema-instance",
		SchemaLoc: "http://gexf.net/1.3 http://gexf.net/1.3/gexf.xsd",
		Version:   "1.3",
		Meta: Meta{
			XMLName:          xml.Name{Local: "meta"},
			LastModifiedDate: time.Now().Format("2006-01-02"),
			Creator:          "The Hacker Dev",
			Description:      "Connections between hosts",
			Keywords:         "connections, hosts",
		},
		Graph: HostMapGraph{
			XMLName:         xml.Name{Local: "graph"},
			Mode:            "static",
			DefaultEdgeType: "directed",
			HostNodes: HostNodes{
				XMLName: xml.Name{Local: "nodes"},
				Nodes:   make(map[string]bool),
			},
			HostEdges: HostEdges{
				XMLName: xml.Name{Local: "edges"},
				Edges:   make(map[string]map[string]bool),
			},
		},
	}

	return &g
}
