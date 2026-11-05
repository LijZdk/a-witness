package witness

import (
	"context"

	"github.com/LijZdk/a-witness/witness/internal/rules"
	"github.com/LijZdk/a-witness/witness/sign"
)

// NotChecked says that some part of the checks did not run, so that a pass
// is never read as wider than it is.
type NotChecked struct {
	Rule   int    // the rule's number in SPEC.md; 0 if no SPEC rule covers it
	Reason string // plain language
}

// SignatureStatus says whether the signatures (rule 15) were checked.
type SignatureStatus int

const (
	// SignaturesNotChecked is the zero value: signatures were skipped, or the
	// record failed before they could vouch for it.
	SignaturesNotChecked SignatureStatus = iota
	// SignaturesValid means rule 15 was checked and held, under the keys the
	// caller's resolver trusts.
	SignaturesValid
)

// Report is what Check found. Report{} is not a pass.
type Report struct {
	// Integrity holds the problems with the record itself (rules 1 to 8 and
	// 15): it is not a genuine, signed record of this mandate.
	Integrity []Problem
	// Rules holds the ways an intact record shows the agent breaking its
	// mandate (rules 9 to 13). Always nil unless RulesRan.
	Rules []Problem
	// Warnings are things worth flagging that do not fail a check, such as
	// rule 14's human_confirmation "never".
	Warnings []Problem
	// NotChecked lists what was left unchecked. It does not affect Pass.
	NotChecked []NotChecked
	// RulesRan is true when the record was intact and the mandate rules were
	// applied to it.
	RulesRan bool
	// Signatures says whether rule 15 was checked and held.
	Signatures SignatureStatus
}

// Pass reports whether the record is genuine, signed, and shows the agent
// obeying every rule that was checked: the rules ran, nothing was found, and
// the signatures were checked and valid. A check without signatures is never
// a pass. Warnings and NotChecked do not affect it; read them alongside.
func (r Report) Pass() bool {
	return r.RulesRan && len(r.Integrity) == 0 && len(r.Rules) == 0 && r.Signatures == SignaturesValid
}

// Check answers both of SPEC.md's verifying questions, in order. First, is
// the record genuine (rules 1 to 8 and 15, as Verify)? Only if so, did the
// agent do what its mandate allowed (rules 9, 10, 11 and 14; 12 and 13 are
// reported as not checked)? Mandate rules checked against a tampered record
// prove nothing, so when the record has integrity problems, Rules stays nil
// and RulesRan false.
//
// keys works as in Verify; pass SkipSignatures to leave rule 15 out, which
// the report records and which stops it being a pass. Signatures valid
// (SignaturesValid) means valid under the keys the caller's resolver trusts:
// Check does not decide whose keys to trust.
//
// A "yes" in the trace is the agent's claim about the principal. Unless the
// principal signed the seal, the report says so in NotChecked.
//
// An error means a document could not be read, or lacks, or has a wrong type
// or value for, something the checks need. It is never a silent skip.
func Check(ctx context.Context, mandateJSON, traceJSON []byte, keys sign.Resolver) (Report, error) {
	var rep Report
	if keys == nil {
		return rep, errNoResolver
	}
	mandate, err := parseObject(mandateJSON, "mandate")
	if err != nil {
		return rep, err
	}
	traceDoc, err := parseObject(traceJSON, "trace")
	if err != nil {
		return rep, err
	}
	problems, err := verify(ctx, mandate, traceDoc, keys)
	if err != nil {
		return rep, err
	}

	signaturesChecked := keys != SkipSignatures
	if !signaturesChecked {
		rep.NotChecked = append(rep.NotChecked, NotChecked{15, "signatures were not checked"})
	}
	if len(problems) > 0 {
		rep.Integrity = problems
		rep.NotChecked = append(rep.NotChecked, NotChecked{0, "record not intact; mandate rules not checked"})
		return rep, nil
	}
	if signaturesChecked {
		rep.Signatures = SignaturesValid
	}

	res, err := rules.Check(mandate, traceDoc, signaturesChecked && sealSignedBy(traceDoc, "principal"))
	if err != nil {
		return rep, err
	}
	rep.RulesRan = true
	rep.Rules = problemsFrom(res.Findings)
	rep.Warnings = problemsFrom(res.Warnings)
	for _, n := range res.NotChecked {
		rep.NotChecked = append(rep.NotChecked, NotChecked{Rule: n.Rule, Reason: n.Reason})
	}
	return rep, nil
}

func problemsFrom(fs []rules.Finding) []Problem {
	var out []Problem
	for _, f := range fs {
		out = append(out, Problem{Rule: f.Rule, Seq: f.Seq, Message: f.Message})
	}
	return out
}

// sealSignedBy reports whether the seal carries a signature from the role.
// It is used only on records whose signatures all verified.
func sealSignedBy(traceDoc map[string]any, role string) bool {
	seal, _ := traceDoc["seal"].(map[string]any)
	sigs, _ := seal["signatures"].([]any)
	for _, s := range sigs {
		if sig, ok := s.(map[string]any); ok && sig["signer"] == role {
			return true
		}
	}
	return false
}
