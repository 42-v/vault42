package audit

import "testing"

// The comment on the svcdoc_ event constants in internal/handler/servicedoc.go
// claimed the prefix was "load-bearing in the same way blob_ is: the audit
// scrubber drops an event class's sensitive keys by prefix". It was not.
// scrubEventMetadata branched on blobEventPrefix alone, so the protection the
// comment described did not exist and a careless caller could have written a
// document body into an audit row that survives account erasure under Art.
// 17(3)(b).
//
// Nothing logged one, so there was no leak. A stated control that does not exist
// is still the defect this release is about, and the cheaper fix was to make the
// sentence true rather than delete it.
func TestScrubEventMetadataDropsServiceDocumentBodies(t *testing.T) {
	for _, key := range []string{"value", "body", "content", "document", "doc", "data", "plaintext", "payload"} {
		t.Run(key, func(t *testing.T) {
			got := scrubEventMetadata("svcdoc_put", map[string]interface{}{
				key:          "the user's private profile JSON",
				"doc_key":    "profile",
				"size_bytes": 412,
			})
			if _, present := got[key]; present {
				t.Errorf("svcdoc_put event kept %q, which is where a document body would land", key)
			}
			if got["doc_key"] != "profile" {
				t.Errorf("doc_key was dropped (%v); it is the identifier that makes the audit trail useful", got["doc_key"])
			}
			if got["size_bytes"] != 412 {
				t.Errorf("size_bytes was dropped (%v)", got["size_bytes"])
			}
		})
	}
}

// The per-class sets must not bleed into each other. A blob event's "label" is
// personal data; a service-document event has no such key, and an admin event
// legitimately carries "name". Dropping one class's keys from another class
// would either over-scrub the admin trail or under-scrub blobs.
func TestScrubEventMetadataKeepsClassesSeparate(t *testing.T) {
	admin := scrubEventMetadata("admin_role_create", map[string]interface{}{"name": "moderator"})
	if admin["name"] != "moderator" {
		t.Errorf("admin_role_create lost its object name (%v); that name is not personal data", admin["name"])
	}

	svcdoc := scrubEventMetadata("svcdoc_delete", map[string]interface{}{"name": "kept"})
	if svcdoc["name"] != "kept" {
		t.Errorf("svcdoc_delete dropped %q, which is the blob class's key, not this one's", "name")
	}

	blob := scrubEventMetadata("blob_create", map[string]interface{}{"label": "medical results"})
	if _, present := blob["label"]; present {
		t.Error("blob_create kept its label, so the blob class stopped being scrubbed")
	}
}
