package authhandlers_test

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// groups maps each route-group source file to the OpenAPI document that
// describes it.
//
// One document per group, not one for the library, because OpenAPI keys
// paths in a map and these groups are mounted independently: POST /login
// exists in both the user group and the operator group, POST /logout in
// three places. They are different operations reachable at different
// prefixes, and a single document cannot say that.
var groups = map[string]string{
	"authhandlers.go": "openapi/user.yaml",
	"team.go":         "openapi/team.yaml",
	"superuser.go":    "openapi/superuser.yaml",
	"pat.go":          "openapi/pat.yaml",
	"device.go":       "openapi/device.yaml",
	"oidc.go":         "openapi/oidc.yaml",
	"passkey.go":      "openapi/passkey.yaml",
	"emaillogin.go":   "openapi/emaillogin.yaml",
}

// TestOpenAPIMatchesTheRoutes is the reason it is safe to hand-write these
// documents.
//
// A hand-written API document drifts the moment a route moves, and drifts
// silently: nothing compiles against it and nothing serves from it. This
// repository has found stale documentation four times in one branch, in
// files far simpler than these. So the routes are read out of the source
// and compared against the documents in both directions -- a route with no
// operation, and an operation with no route, are both failures.
//
// It checks paths and methods, which is what drifts. It cannot check that a
// described schema still matches its Go struct; that gap is real and named
// in each document's description rather than left to be discovered.
func TestOpenAPIMatchesTheRoutes(t *testing.T) {
	for source, doc := range groups {
		t.Run(source, func(t *testing.T) {
			routes, err := routesIn(source)
			if err != nil {
				t.Fatal(err)
			}
			if len(routes) == 0 {
				t.Fatalf("no routes found in %s; the extractor has stopped working", source)
			}
			documented, err := operationsIn(doc)
			if err != nil {
				t.Fatal(err)
			}

			for _, r := range diff(routes, documented) {
				t.Errorf("%s serves %s but %s does not describe it", source, r, doc)
			}
			for _, r := range diff(documented, routes) {
				t.Errorf("%s describes %s but %s does not serve it", doc, r, source)
			}
		})
	}
}

var (
	// Matches mux.HandleFunc("POST /path", ...) in a route group.
	routeRe = regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) ([^"]+)"`)
	// Matches a path key and the method keys nested under it. Deliberately
	// crude: it only has to read the documents in this directory, and a
	// real YAML parser would be a dependency for one test.
	pathRe   = regexp.MustCompile(`(?m)^  (/\S*):\s*$`)
	methodRe = regexp.MustCompile(`(?m)^    (get|put|post|delete|patch|options|head):\s*$`)
)

// routesIn reads the routes a group registers. Duplicates collapse: the
// user group registers POST /logout twice, once per session mode, and both
// are the same operation to a client.
func routesIn(source string) (map[string]bool, error) {
	b, err := os.ReadFile(source)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, m := range routeRe.FindAllStringSubmatch(string(b), -1) {
		out[m[1]+" "+m[2]] = true
	}
	return out, nil
}

// operationsIn reads method+path pairs out of an OpenAPI document's paths
// section.
func operationsIn(doc string) (map[string]bool, error) {
	b, err := os.ReadFile(doc)
	if err != nil {
		return nil, err
	}
	text := string(b)
	start := strings.Index(text, "\npaths:\n")
	if start < 0 {
		return nil, fmt.Errorf("%s: no paths section", doc)
	}
	body := text[start:]
	if end := strings.Index(body, "\ncomponents:\n"); end >= 0 {
		body = body[:end]
	}

	out := map[string]bool{}
	locs := pathRe.FindAllStringSubmatchIndex(body, -1)
	for i, loc := range locs {
		path := body[loc[2]:loc[3]]
		next := len(body)
		if i+1 < len(locs) {
			next = locs[i+1][0]
		}
		for _, m := range methodRe.FindAllStringSubmatch(body[loc[1]:next], -1) {
			out[strings.ToUpper(m[1])+" "+path] = true
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: parsed no operations; the extractor has stopped working", doc)
	}
	return out, nil
}

func diff(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if !b[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
