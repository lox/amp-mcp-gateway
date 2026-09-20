package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"
)

var grantIdentity = ampIdentity{UserID: "user-owner", ThreadID: "T-01a0b6d8-e50f-7723-941c-60bca63723ba", ProjectID: "project-a", WorkspaceID: "workspace-a"}

func TestScopedExecution(t *testing.T) {
	g, s, b := fixture(t)
	g.cfg.AmpUserID = grantIdentity.UserID
	ctx := withAmpIdentity(t.Context(), grantIdentity)
	o, err := g.submit(ctx, input("grant-source", "human-reviewed"))
	if err != nil {
		t.Fatal(err)
	}
	if g.approveScope(ctx, o.ID, "stranger", "thread") == nil {
		t.Fatal("wrong browser owner accepted")
	}
	if err := g.approveScope(ctx, o.ID, "owner", "thread"); err != nil {
		t.Fatal(err)
	}
	later, err := g.submit(ctx, input("grant-later", "different future arguments"))
	if err != nil || later.Status != "ready" || later.GrantID != o.ID {
		t.Fatalf("future call: %v %v", later, err)
	}
	other := grantIdentity
	other.ThreadID = "T-01a0b6d8-e50f-7723-941c-60bca63723bb"
	blocked, err := g.submit(withAmpIdentity(ctx, other), input("other-thread", "must wait"))
	if err != nil || blocked.Status != "pending" {
		t.Fatal("other thread authorized")
	}
	bad := input("bad-schema", "invalid")
	bad.Calls[0].Arguments["text"] = 3
	if _, err := g.submit(ctx, bad); err == nil {
		t.Fatal("grant bypassed schema")
	}
	runWorker(t, g)
	await(t, s, o.ID, "succeeded")
	done := await(t, s, later.ID, "succeeded")
	if !strings.Contains(string(done.Result), "different future arguments") || b.calls.Load() != 2 {
		t.Fatal("wrong execution result/count")
	}
	if err := s.RevokeGrant(ctx, o.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	again, err := g.submit(ctx, input("grant-later", "different future arguments"))
	if err != nil || again.Status != "succeeded" {
		t.Fatal("revocation broke idempotency")
	}
	fresh, err := g.submit(ctx, input("after-revoke", "must wait again"))
	if err != nil || fresh.Status != "pending" {
		t.Fatal("revoked grant reused")
	}
}

func TestGrantStaleConfiguration(t *testing.T) {
	for name, change := range map[string]func(*Config){
		"tool":       func(c *Config) { c.Tools[0].Name = "delete" },
		"schema":     func(c *Config) { c.Tools[0].InputSchema["description"] = "Changed schema" },
		"policy":     func(c *Config) { c.Tools[0].Policy = "deny" },
		"connection": func(c *Config) { c.Connections[0].URL = "http://localhost/other" },
		"owner":      func(c *Config) { c.OwnerSubject = "another-owner" },
	} {
		t.Run(name, func(t *testing.T) {
			g, s, b := fixture(t)
			g.cfg.AmpUserID = grantIdentity.UserID
			g, err := New(g.cfg, s, b)
			if err != nil {
				t.Fatal(err)
			}
			ctx := withAmpIdentity(t.Context(), grantIdentity)
			o, err := g.submit(ctx, input("grant-source", "reviewed"))
			if err != nil {
				t.Fatal(err)
			}
			if err := g.approveScope(ctx, o.ID, "owner", "project"); err != nil {
				t.Fatal(err)
			}
			queued, err := g.submit(ctx, input("grant-queued", "before config change"))
			if err != nil || queued.Status != "ready" {
				t.Fatal("grant not used")
			}
			change(&g.cfg)
			next, err := New(g.cfg, s, b)
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := next.submit(ctx, input("after-change", "after config change"))
			if err != nil || fresh.GrantID != "" || fresh.Status == "ready" {
				t.Fatalf("stale grant reused: %v %v", fresh, err)
			}
			runWorker(t, next)
			await(t, s, queued.ID, "denied")
			if b.calls.Load() != 0 {
				t.Fatal("stale queued call dispatched")
			}
		})
	}
}

func TestScopeControlsRequireSignedIdentity(t *testing.T) {
	for _, identity := range []ampIdentity{{}, {UserID: grantIdentity.UserID, ThreadID: grantIdentity.ThreadID}, grantIdentity} {
		g, s, _ := fixture(t)
		if identity.UserID != "" {
			g.cfg.AmpUserID = identity.UserID
		}
		ctx := withAmpIdentity(t.Context(), identity)
		o, err := g.submit(ctx, input("scope-controls", "review"))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/operations/"+o.ID, nil)
		r.SetPathValue("id", o.ID)
		w := httptest.NewRecorder()
		g.operation(w, r)
		body := w.Body.String()
		if !strings.Contains(body, "Approve once") || strings.Contains(body, "Approve this thread") != (identity.UserID != "") || strings.Contains(body, "Approve this project") != (identity.ProjectID != "") {
			t.Fatal("incorrect scope controls")
		}
		if identity.ProjectID == "" && g.approveScope(ctx, o.ID, "owner", "project") == nil {
			t.Fatal("unverified project approved")
		}
		grants, err := s.Grants(ctx, "owner")
		if err != nil || len(grants) != 0 {
			t.Fatal("render created grant")
		}
	}
}

func TestOneTimeApprovalDoesNotGrant(t *testing.T) {
	g, s, _ := fixture(t)
	g.cfg.AmpUserID = grantIdentity.UserID
	ctx := withAmpIdentity(t.Context(), grantIdentity)
	o, err := g.submit(ctx, input("once-source", "one time"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Decide(ctx, o.ID, "owner", true); err != nil {
		t.Fatal(err)
	}
	later, err := g.submit(ctx, input("once-later", "must still wait"))
	if err != nil || later.Status != "pending" {
		t.Fatal("one-time consent widened")
	}
	// An expired/denied operation cannot be used to mint future authority.
	if err := s.Decide(ctx, later.ID, "owner", false); err != nil {
		t.Fatal(err)
	}
	if g.approveScope(ctx, later.ID, "owner", "thread") == nil {
		t.Fatal("denied operation granted")
	}
	grants, err := s.Grants(ctx, "owner")
	if err != nil || len(grants) != 0 {
		t.Fatal("unexpected grants")
	}
}

func TestRetryCannotAddProjectAuthority(t *testing.T) {
	g, _, _ := fixture(t)
	g.cfg.AmpUserID = grantIdentity.UserID
	legacy := grantIdentity
	legacy.ProjectID, legacy.WorkspaceID = "", ""
	in := input("legacy-retry", "immutable request")
	o, err := g.submit(withAmpIdentity(t.Context(), legacy), in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.submit(withAmpIdentity(t.Context(), grantIdentity), in)
	if err != nil || got.Digest != o.Digest || got.AmpProjectID != "" || got.AmpWorkspaceID != "" {
		t.Fatalf("retry changed stored authority: %v %v", got, err)
	}
	if g.approveScope(t.Context(), o.ID, "owner", "project") == nil {
		t.Fatal("retry added project authority")
	}
}
