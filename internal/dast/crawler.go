package dast

import (
	"context"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"mantis/internal/findings"
	"mantis/internal/httpclient"
)

type Crawler struct {
	Client      *httpclient.Client
	MaxDepth    int
	MaxRequests int
	Headers     map[string]string // applied to every crawl request, e.g. resolved auth (authenticated crawling)
}

type crawlItem struct {
	url   string
	depth int
}

// Crawl does a plain breadth-first crawl from seed, capped by MaxDepth and
// MaxRequests so it can't run away on a large site. Scope is enforced by the
// underlying httpclient.Client (AllowedHosts) - anything off-host just gets
// dropped from the queue instead of followed. We run the passive checks
// against each page as we fetch it here, rather than in a second pass, so
// we're not doubling the request count just to analyze what we already have.
func (c *Crawler) Crawl(ctx context.Context, seed, environment string, redactor *httpclient.Redactor) (*AttackSurface, []findings.Finding, error) {
	visited := map[string]bool{}
	formSeen := map[string]bool{}
	queue := []crawlItem{{url: seed, depth: 0}}
	surface := &AttackSurface{}
	var passiveFindings []findings.Finding
	requests := 0

	maxDepth := c.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 2
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if visited[item.url] {
			continue
		}
		visited[item.url] = true

		if item.depth > maxDepth {
			continue
		}
		if c.MaxRequests > 0 && requests >= c.MaxRequests {
			break
		}

		resp, err := c.Client.Do(ctx, httpclient.Request{Method: "GET", URL: item.url, Headers: c.Headers})
		requests++
		if err != nil {
			continue
		}
		surface.URLs = append(surface.URLs, item.url)
		passiveFindings = append(passiveFindings, RunPassiveChecks(item.url, environment, resp, redactor)...)

		if !isHTML(resp) {
			continue
		}

		links, forms := parseHTML(item.url, resp.Body)
		for _, l := range links {
			if !visited[l] {
				queue = append(queue, crawlItem{url: l, depth: item.depth + 1})
			}
		}
		for _, f := range forms {
			key := f.Method + " " + f.Action
			if !formSeen[key] {
				formSeen[key] = true
				surface.Forms = append(surface.Forms, f)
			}
		}
	}

	return surface, passiveFindings, nil
}

func isHTML(resp *httpclient.Response) bool {
	ct := resp.Headers.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "text/html")
}

func parseHTML(baseURL string, body []byte) (links []string, forms []Form) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil
	}
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, nil
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "a", "link":
				if href := attr(n, "href"); href != "" {
					if abs := resolve(base, href); abs != "" {
						links = append(links, abs)
					}
				}
			case "form":
				f := Form{Method: "GET", Inputs: map[string]string{}}
				if m := attr(n, "method"); m != "" {
					f.Method = strings.ToUpper(m)
				}
				if a := attr(n, "action"); a != "" {
					f.Action = resolve(base, a)
				} else {
					f.Action = base.String()
				}
				collectInputs(n, &f)
				forms = append(forms, f)
				return // inputs already collected; don't descend twice
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links, forms
}

func collectInputs(n *html.Node, f *Form) {
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "select", "textarea":
				name := attr(n, "name")
				typ := attr(n, "type")
				if typ == "" {
					typ = "text"
				}
				if name != "" {
					f.Inputs[name] = typ
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func resolve(base *url.URL, href string) string {
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := base.ResolveReference(u)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	resolved.Fragment = ""
	return resolved.String()
}
