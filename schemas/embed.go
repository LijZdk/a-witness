// Package schemas embeds the JSON Schemas (2020-12) that describe a mandate
// and a trace, so Go code can check documents against exactly the files in
// this directory.
package schemas

import (
	_ "embed"
	"slices"
)

// The $id of each schema. The trace schema refers to the mandate schema by
// the relative reference "mandate.schema.json", which resolves against these.
const (
	MandateID = "https://a-witness.dev/schemas/0.1/mandate.schema.json"
	TraceID   = "https://a-witness.dev/schemas/0.1/trace.schema.json"
)

//go:embed mandate.schema.json
var mandateJSON []byte

//go:embed trace.schema.json
var traceJSON []byte

// MandateJSON returns a copy of mandate.schema.json.
func MandateJSON() []byte { return slices.Clone(mandateJSON) }

// TraceJSON returns a copy of trace.schema.json.
func TraceJSON() []byte { return slices.Clone(traceJSON) }
