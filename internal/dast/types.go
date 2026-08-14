// Package dast is the automated scan mode: crawl the app, run the passive
// checks against everything we fetch along the way, then hand the discovered
// surface to the template engine for active testing.
package dast

// Form is an HTML form discovered during crawling.
type Form struct {
	Action string
	Method string
	Inputs map[string]string // field name -> input type
}

// AttackSurface is everything the crawler found: candidate endpoints and
// forms to feed into passive/active testing.
type AttackSurface struct {
	URLs          []string
	Forms         []Form
	Cookies       []string // names of cookies observed in Set-Cookie headers during crawl
	JSONEndpoints []string // URLs that responded with Content-Type: application/json
}
