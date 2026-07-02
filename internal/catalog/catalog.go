package catalog

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Body is either an inline string or a file reference (relative to the catalog dir).
type Body struct {
	Inline *string `yaml:"inline"`
	File   string  `yaml:"file"`
}

// Part is one part of a multipart response.
type Part struct {
	Headers map[string]string `yaml:"headers"`
	Body    Body              `yaml:"body"`
}

// Multipart describes a boundary-delimited response.
type Multipart struct {
	Type  string `yaml:"type"`
	Parts []Part `yaml:"parts"`
}

// Entry is a complete decoy response definition.
type Entry struct {
	Status    int               `yaml:"status"`
	Headers   map[string]string `yaml:"headers"`
	Body      *Body             `yaml:"body"`
	Multipart *Multipart        `yaml:"multipart"`

	// resolved at load time
	body        []byte
	contentType string // overrides Headers Content-Type (multipart w/ boundary)
}

// Catalog is a set of named decoy responses.
type Catalog struct {
	entries map[string]*Entry
}

// Load reads <dir>/catalog.yaml and resolves all referenced body files, failing
// if any is missing (so a bad catalog is rejected before it is swapped in).
func Load(dir string) (*Catalog, error) {
	path := filepath.Join(dir, "catalog.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}
	var defs map[string]*Entry
	if err := yaml.Unmarshal(raw, &defs); err != nil {
		return nil, fmt.Errorf("parse catalog: %w", err)
	}
	c := &Catalog{entries: make(map[string]*Entry, len(defs))}
	for name, e := range defs {
		if e == nil {
			return nil, fmt.Errorf("catalog entry %q is empty", name)
		}
		if err := e.resolve(dir, name); err != nil {
			return nil, err
		}
		c.entries[name] = e
	}
	return c, nil
}

func readBody(dir string, b Body, ctx string) ([]byte, error) {
	switch {
	case b.Inline != nil && b.File != "":
		return nil, fmt.Errorf("%s: body has both inline and file", ctx)
	case b.Inline != nil:
		return []byte(*b.Inline), nil
	case b.File != "":
		p := filepath.Join(dir, filepath.Clean("/"+b.File)) // prevent path escape
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: read body file: %w", ctx, err)
		}
		return data, nil
	default:
		return nil, nil // empty body allowed (e.g. 204)
	}
}

func (e *Entry) resolve(dir, name string) error {
	if e.Status == 0 {
		e.Status = http.StatusOK
	}
	if e.Multipart != nil {
		if e.Body != nil {
			return fmt.Errorf("catalog %q: cannot set both body and multipart", name)
		}
		return e.resolveMultipart(dir, name)
	}
	if e.Body != nil {
		body, err := readBody(dir, *e.Body, "catalog "+name)
		if err != nil {
			return err
		}
		e.body = body
	}
	return nil
}

func (e *Entry) resolveMultipart(dir, name string) error {
	if e.Multipart.Type == "" {
		e.Multipart.Type = "multipart/mixed"
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// Deterministic boundary so Content-Length is stable across renders.
	if err := mw.SetBoundary("mirage-chaff-" + name); err != nil {
		return fmt.Errorf("catalog %q: %w", name, err)
	}
	for idx, part := range e.Multipart.Parts {
		h := make(textproto.MIMEHeader)
		for k, v := range part.Headers {
			h.Set(k, v)
		}
		pw, err := mw.CreatePart(h)
		if err != nil {
			return fmt.Errorf("catalog %q part %d: %w", name, idx, err)
		}
		body, err := readBody(dir, part.Body, fmt.Sprintf("catalog %q part %d", name, idx))
		if err != nil {
			return err
		}
		if _, err := pw.Write(body); err != nil {
			return err
		}
	}
	if err := mw.Close(); err != nil {
		return err
	}
	e.body = buf.Bytes()
	// Honor the requested multipart type (mixed/form-data/…) with the boundary.
	e.contentType = fmt.Sprintf("%s; boundary=%s", e.Multipart.Type, mw.Boundary())
	return nil
}

// Names returns the sorted list of catalog entry names.
func (c *Catalog) Names() []string {
	names := make([]string, 0, len(c.entries))
	for n := range c.entries {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Get returns the named entry.
func (c *Catalog) Get(name string) (*Entry, bool) {
	e, ok := c.entries[name]
	return e, ok
}

// Render writes the named decoy response. If the name is unknown it returns an
// error; callers should fall back to a safe default (204).
func (c *Catalog) Render(w http.ResponseWriter, name string) error {
	e, ok := c.entries[name]
	if !ok {
		return fmt.Errorf("catalog entry %q not found", name)
	}
	e.write(w)
	return nil
}

func (e *Entry) write(w http.ResponseWriter) {
	for k, v := range e.Headers {
		w.Header().Set(k, v)
	}
	if e.contentType != "" {
		w.Header().Set("Content-Type", e.contentType)
	}
	if e.body != nil {
		w.Header().Set("Content-Length", strconv.Itoa(len(e.body)))
	}
	w.WriteHeader(e.Status)
	if len(e.body) > 0 {
		_, _ = w.Write(e.body)
	}
}
