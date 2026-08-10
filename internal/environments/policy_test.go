package environments

import "testing"

func TestPolicyFor(t *testing.T) {
	cases := []struct {
		level string
		want  SecurityLevel
	}{
		{"aggressive", LevelAggressive},
		{"AGGRESSIVE", LevelAggressive}, // case-insensitive
		{" standard ", LevelStandard},   // trims whitespace
		{"passive", LevelPassive},
		{"", LevelPassive},          // no level configured -> safest
		{"aggresive", LevelPassive}, // typo -> safest, never a silent escalation
		{"active", LevelPassive},    // not a real level -> safest
	}
	for _, c := range cases {
		if got := PolicyFor(c.level).Level; got != c.want {
			t.Errorf("PolicyFor(%q).Level = %q, want %q", c.level, got, c.want)
		}
	}
}

// This is the actual safety property the whole policy design leans on: a
// mistyped or missing security_level must never grant MORE than passive
// allows, in any dimension.
func TestPolicyFor_UnknownNeverExceedsPassive(t *testing.T) {
	passive := PolicyFor(string(LevelPassive))
	unknown := PolicyFor("definitely-not-a-real-level")

	if unknown.ActiveDAST && !passive.ActiveDAST {
		t.Error("unknown security_level enabled ActiveDAST when passive doesn't")
	}
	if unknown.Destructive && !passive.Destructive {
		t.Error("unknown security_level enabled Destructive when passive doesn't")
	}
	if unknown.RateLimit > passive.RateLimit {
		t.Errorf("unknown security_level got a higher rate limit (%v) than passive (%v)", unknown.RateLimit, passive.RateLimit)
	}
	if unknown.MaxRequests > passive.MaxRequests {
		t.Errorf("unknown security_level got more max requests (%v) than passive (%v)", unknown.MaxRequests, passive.MaxRequests)
	}
}

func TestPolicyLevels_AreOrderedBySafety(t *testing.T) {
	aggressive := PolicyFor(string(LevelAggressive))
	standard := PolicyFor(string(LevelStandard))
	passive := PolicyFor(string(LevelPassive))

	if !aggressive.Destructive {
		t.Error("aggressive should permit destructive testing")
	}
	if standard.Destructive {
		t.Error("standard should not permit destructive testing")
	}
	if passive.ActiveDAST {
		t.Error("passive should not permit active DAST")
	}
	if !passive.PassiveDAST {
		t.Error("passive should still permit passive DAST")
	}
	if !passive.Smoke {
		t.Error("passive should still permit smoke testing - it doesn't touch security posture")
	}

	if !(aggressive.RateLimit >= standard.RateLimit && standard.RateLimit >= passive.RateLimit) {
		t.Errorf("rate limits should decrease with caution: aggressive=%v standard=%v passive=%v",
			aggressive.RateLimit, standard.RateLimit, passive.RateLimit)
	}
}
