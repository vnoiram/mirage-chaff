package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Action names understood by the engine.
const (
	ActionStub            = "stub"
	ActionForwardScrubbed = "forward-scrubbed"
	ActionForwardMimic    = "forward-mimic"
	ActionForwardAsis     = "forward-asis"
	ActionPassthrough     = "passthrough"
)

func validAction(a string) bool {
	switch a {
	case ActionStub, ActionForwardScrubbed, ActionForwardMimic, ActionForwardAsis, ActionPassthrough:
		return true
	}
	return false
}

// Match constrains which requests a rule applies to. Empty fields match anything.
type Match struct {
	Domain string   `yaml:"domain"`
	Path   string   `yaml:"path"`
	Method []string `yaml:"method"`
}

// Rule is one policy rule.
type Rule struct {
	Name     string `yaml:"name"`
	Priority int    `yaml:"priority"`
	Match    Match  `yaml:"match"`
	Action   string `yaml:"action"`
	Catalog  string `yaml:"catalog"`

	domainRe *regexp.Regexp
	pathRe   *regexp.Regexp
	methods  map[string]bool
}

// Default is the action applied when no rule matches.
type Default struct {
	Action  string `yaml:"action"`
	Catalog string `yaml:"catalog"`
}

type policyFile struct {
	Rules   []*Rule  `yaml:"rules"`
	Default *Default `yaml:"default"`
}

// Decision is the outcome of matching a request.
type Decision struct {
	Action  string
	Catalog string
	Rule    string // "" when the default was used
	Matched bool
}

// Ruleset is an immutable, priority-ordered set of compiled rules plus a default.
type Ruleset struct {
	rules []*Rule
	def   Decision
}

// Load reads every *.yaml/*.yml in dir, compiles the rules, and returns a
// priority-ordered Ruleset. It fails on any invalid rule so a bad policy set is
// never swapped in (validate-then-swap, design doc D-2). A missing/empty dir
// yields a ruleset with just the safe default (stub 204).
func Load(dir string) (*Ruleset, error) {
	rs := &Ruleset{def: Decision{Action: ActionStub, Catalog: "beacon-204"}}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return rs, nil
		}
		return nil, fmt.Errorf("read policy dir: %w", err)
	}

	names := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var pf policyFile
		if err := yaml.Unmarshal(raw, &pf); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, r := range pf.Rules {
			if err := r.compile(); err != nil {
				return nil, fmt.Errorf("%s: rule %q: %w", e.Name(), r.Name, err)
			}
			if names[r.Name] {
				return nil, fmt.Errorf("%s: duplicate rule name %q", e.Name(), r.Name)
			}
			names[r.Name] = true
			rs.rules = append(rs.rules, r)
		}
		if pf.Default != nil {
			if !validAction(pf.Default.Action) {
				return nil, fmt.Errorf("%s: invalid default action %q", e.Name(), pf.Default.Action)
			}
			rs.def = Decision{Action: pf.Default.Action, Catalog: pf.Default.Catalog}
		}
	}

	// Stable priority order (lower first); ties keep file order.
	sort.SliceStable(rs.rules, func(i, j int) bool { return rs.rules[i].Priority < rs.rules[j].Priority })
	return rs, nil
}

// ValidateBytes parses and compiles a single policy.d YAML document, returning
// an error if any rule is invalid. Used by the admin editor before writing.
func ValidateBytes(raw []byte) error {
	var pf policyFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return err
	}
	for _, r := range pf.Rules {
		if err := r.compile(); err != nil {
			return fmt.Errorf("rule %q: %w", r.Name, err)
		}
	}
	if pf.Default != nil && !validAction(pf.Default.Action) {
		return fmt.Errorf("invalid default action %q", pf.Default.Action)
	}
	return nil
}

func (r *Rule) compile() error {
	if r.Name == "" {
		return fmt.Errorf("rule has no name")
	}
	if !validAction(r.Action) {
		return fmt.Errorf("invalid action %q", r.Action)
	}
	if r.Action == ActionStub && r.Catalog == "" {
		return fmt.Errorf("stub action requires a catalog entry")
	}
	re, err := compileGlob(r.Match.Domain)
	if err != nil {
		return fmt.Errorf("bad domain glob: %w", err)
	}
	r.domainRe = re
	re, err = compileGlob(r.Match.Path)
	if err != nil {
		return fmt.Errorf("bad path glob: %w", err)
	}
	r.pathRe = re
	if len(r.Match.Method) > 0 {
		r.methods = make(map[string]bool, len(r.Match.Method))
		for _, m := range r.Match.Method {
			r.methods[strings.ToUpper(m)] = true
		}
	}
	return nil
}

// Rules returns the compiled rules in priority order (read-only view for the UI).
func (rs *Ruleset) Rules() []*Rule { return rs.rules }

// Default returns the default decision.
func (rs *Ruleset) Default() Decision { return rs.def }

// CatalogRefs returns every catalog name referenced by stub rules or the default,
// so the caller can verify they exist before swapping the ruleset in.
func (rs *Ruleset) CatalogRefs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, r := range rs.rules {
		if r.Action == ActionStub {
			add(r.Catalog)
		}
	}
	if rs.def.Action == ActionStub {
		add(rs.def.Catalog)
	}
	return out
}

// Match returns the decision for a request. domain is the request authority/Host
// (or SNI), path is the URL path, method is the HTTP method.
func (rs *Ruleset) Match(domain, path, method string) Decision {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	method = strings.ToUpper(method)
	for _, r := range rs.rules {
		if r.methods != nil && !r.methods[method] {
			continue
		}
		if !r.domainRe.MatchString(domain) {
			continue
		}
		if !r.pathRe.MatchString(path) {
			continue
		}
		return Decision{Action: r.Action, Catalog: r.Catalog, Rule: r.Name, Matched: true}
	}
	d := rs.def
	d.Matched = false
	return d
}

// compileGlob turns a shell-style glob into an anchored regexp where '*' matches
// any run of characters (including '.' and '/') and '?' matches one. An empty
// pattern matches everything.
func compileGlob(glob string) (*regexp.Regexp, error) {
	if glob == "" {
		return regexp.MustCompile(`^.*$`), nil
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
