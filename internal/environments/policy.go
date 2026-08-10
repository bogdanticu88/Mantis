// Package environments is where "which environment am I pointed at, and how
// aggressive am I allowed to be against it" lives - environment profiles and
// the policy (smoke/passive/active/destructive, rate limits) tied to each
// one. Production should always resolve to the safest policy.
package environments

import "strings"

type SecurityLevel string

const (
	LevelAggressive SecurityLevel = "aggressive"
	LevelStandard   SecurityLevel = "standard"
	LevelPassive    SecurityLevel = "passive"
)

// Policy is the resolved set of behavior limits for a security level.
type Policy struct {
	Level          SecurityLevel
	Smoke          bool
	PassiveDAST    bool
	ActiveDAST     bool
	Destructive    bool
	RateLimit      float64 // requests/sec
	MaxConcurrency int
	MaxCrawlDepth  int
	MaxRequests    int
}

// defaultPolicies holds the numbers for each level. "passive" doubles as the
// safe fallback for any environment that doesn't explicitly opt into
// something more permissive - production should never end up more
// aggressive than this by accident.
var defaultPolicies = map[SecurityLevel]Policy{
	LevelAggressive: {
		Level: LevelAggressive, Smoke: true, PassiveDAST: true, ActiveDAST: true, Destructive: true,
		RateLimit: 25, MaxConcurrency: 10, MaxCrawlDepth: 5, MaxRequests: 5000,
	},
	LevelStandard: {
		Level: LevelStandard, Smoke: true, PassiveDAST: true, ActiveDAST: true, Destructive: false,
		RateLimit: 10, MaxConcurrency: 5, MaxCrawlDepth: 3, MaxRequests: 2000,
	},
	LevelPassive: {
		Level: LevelPassive, Smoke: true, PassiveDAST: true, ActiveDAST: false, Destructive: false,
		RateLimit: 2, MaxConcurrency: 2, MaxCrawlDepth: 1, MaxRequests: 200,
	},
}

// PolicyFor resolves a named security level, falling back to the safest
// policy (passive) for anything unrecognized rather than erroring - an
// operator typo in an environment profile must never silently grant
// aggressive/active/destructive testing against an unintended target.
func PolicyFor(level string) Policy {
	l := SecurityLevel(strings.ToLower(strings.TrimSpace(level)))
	if p, ok := defaultPolicies[l]; ok {
		return p
	}
	return defaultPolicies[LevelPassive]
}
