package gexf

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sync"
	"time"
)

// PathHostsMapGexf is a Gexf file that contains a map of paths for one host and their connections to other hosts.
// It uses a dynamic graph with start times for each node and edge.
type PathHostsMapGexf struct {
	mu        sync.RWMutex
	XMLName   xml.Name `xml:"gexf"`
	Xmlns     string   `xml:"xmlns,attr"`
	Xsi       string   `xml:"xmlns:xsi,attr"`
	SchemaLoc string   `xml:"xsi:schemaLocation,attr"`
	Version   string   `xml:"version,attr"`
	Meta      Meta
	Graph     PathHostsGraph
}

type PathHostsGraph struct {
	XMLName            xml.Name `xml:"graph"`
	Mode               string   `xml:"mode,attr"`
	TimeFormat         string   `xml:"timeformat,attr,omitempty"`
	TimeRepresentation string   `xml:"timerepresentation,attr,omitempty"`
	DefaultEdgeType    string   `xml:"defaultedgetype,attr,omitempty"`
	Attributes         Attributes
	PathHostsNodes     PathHostsNodes
	PathHostEdges      HostEdges
}

// PathHostsNodes contains a map of nodes, where the key is the node, and the value is the classification ID.
type PathHostsNodes struct {
	XMLName xml.Name       `xml:"nodes"`
	Nodes   map[string]int `xml:"node"`
	Count   int            `xml:"count,attr"`
}

// MarshalXML is a custom XML marshaller for PathHostsNodes.
func (n PathHostsNodes) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
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
	for k, cid := range n.Nodes {
		// Create the node object, with the classification ID as an attribute
		var node Node
		node = Node{
			Id:    k,
			Label: k,
			Attvalues: Attvalues{Attvalues: []Attvalue{
				{
					For:   "0",
					Value: fmt.Sprintf("%d", cid),
				},
			}},
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

// Write creates the XML for the Gexf struct and writes it to the provided writer.
// It returns the number of bytes written and any errors, conforming to the io.Writer interface.
func (g *PathHostsMapGexf) Write(w io.Writer) (int, error) {
	// Set the nodes and edges counts before writing, to optimize the parser reads
	g.Graph.PathHostsNodes.Count = len(g.Graph.PathHostsNodes.Nodes)
	g.Graph.PathHostEdges.Count = 0
	for _, m := range g.Graph.PathHostEdges.Edges {
		g.Graph.PathHostEdges.Count += len(m)
	}

	// Create a buffer to hold the encoded XML data
	buf := new(bytes.Buffer)

	// Create the XML encoder
	e := xml.NewEncoder(buf)

	// Start with the XML processing instructions
	if err := e.EncodeToken(xml.ProcInst{Target: "xml", Inst: []byte(`version="1.0" encoding="UTF-8"`)}); err != nil {
		return 0, fmt.Errorf("unable to encode XML processing instructions: %w", err)
	}

	// DEBUG: Add indentation
	e.Indent("", "  ")

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

// AddPath adds a path to the path hosts map graph.
func (g *PathHostsMapGexf) AddPath(path string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Skip empty paths
	if path == "" {
		return
	}

	// Add the path
	g.Graph.PathHostsNodes.Nodes[path] = -1
}

// AddClassification adds a classification ID to the given path in the path hosts map graph.
// If the path does not exist in the graph, it will be added.
func (g *PathHostsMapGexf) AddClassification(path string, cid int) {
	// Add the path to the path hosts map graph.
	// Empty paths are skipped in the AddPath function.
	g.AddPath(path)

	g.mu.Lock()
	defer g.mu.Unlock()

	// Add the classification ID to the path
	g.Graph.PathHostsNodes.Nodes[path] = cid
}

// AddConnection adds a connection (edge) to the path hosts map graph.
// If the edge already exists, it will be skipped.
// If either of the paths in the edge do not exist, they will be added to the path hosts map graph.
func (g *PathHostsMapGexf) AddConnection(sourcePath, targetPath string) {
	// Add the source and target paths to the path hosts map graph.
	// Empty paths are skipped in the AddPath function.
	g.AddPath(sourcePath)
	g.AddPath(targetPath)

	if sourcePath == "" || targetPath == "" {
		// No connection to add, only paths
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// Check for existing source path in the edges map
	if _, ok := g.Graph.PathHostEdges.Edges[sourcePath]; !ok {
		// Add the source path to the edges map
		g.Graph.PathHostEdges.Edges[sourcePath] = make(map[string]bool)
	}

	// Add the target path to the source path edges map
	g.Graph.PathHostEdges.Edges[sourcePath][targetPath] = true
}

// CreatePathHostsMapGexf creates a new PathHostsMapGexf struct.
func CreatePathHostsMapGexf() *PathHostsMapGexf {
	// Create the host map graph
	g := PathHostsMapGexf{
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
			Description:      "Connections from paths to hosts",
			Keywords:         "connections, hosts, paths",
		},
		Graph: PathHostsGraph{
			XMLName:         xml.Name{Local: "graph"},
			Mode:            "static",
			DefaultEdgeType: "directed",
			Attributes: Attributes{
				Class: "node",
				Attributes: []Attribute{
					{
						Id:    "0",
						Title: "Classification",
						Type:  "integer",
					},
				},
			},
			PathHostsNodes: PathHostsNodes{
				XMLName: xml.Name{Local: "nodes"},
				Nodes:   make(map[string]int),
			},
			PathHostEdges: HostEdges{
				XMLName: xml.Name{Local: "edges"},
				Edges:   make(map[string]map[string]bool),
			},
		},
	}

	return &g
}
