package schemas

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestEmbeddedBytesEqualFilesOnDisk(t *testing.T) {
	for _, tc := range []struct {
		file string
		got  []byte
	}{
		{"mandate.schema.json", MandateJSON()},
		{"trace.schema.json", TraceJSON()},
	} {
		disk, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		if len(disk) == 0 || !bytes.Equal(disk, tc.got) {
			t.Errorf("%s: embedded copy differs from the file on disk", tc.file)
		}
	}
}

func TestSchemaIDsMatchConstants(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"mandate", MandateJSON(), MandateID},
		{"trace", TraceJSON(), TraceID},
	} {
		var doc struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(tc.raw, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.ID != tc.want {
			t.Errorf("%s: $id is %q, constant is %q", tc.name, doc.ID, tc.want)
		}
	}
}

func TestAccessorsReturnCopies(t *testing.T) {
	a := MandateJSON()
	a[0] = 'X'
	if MandateJSON()[0] == 'X' {
		t.Error("MandateJSON shares its backing array with the caller")
	}
	b := TraceJSON()
	b[0] = 'X'
	if TraceJSON()[0] == 'X' {
		t.Error("TraceJSON shares its backing array with the caller")
	}
}
