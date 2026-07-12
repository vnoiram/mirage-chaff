package admin

import "testing"

func TestMapGroupsToRole(t *testing.T) {
	rm := map[string]Role{
		"homelab-admins":   RoleAdmin,
		"homelab-ops":      RoleEditor,
		"homelab-readonly": RoleViewer,
	}
	cases := []struct {
		groups []string
		want   Role
		ok     bool
	}{
		{[]string{"homelab-readonly"}, RoleViewer, true},
		{[]string{"homelab-ops"}, RoleEditor, true},
		{[]string{"homelab-admins"}, RoleAdmin, true},
		// Highest privilege wins when multiple map.
		{[]string{"homelab-readonly", "homelab-admins", "homelab-ops"}, RoleAdmin, true},
		{[]string{"homelab-ops", "homelab-readonly"}, RoleEditor, true},
		// No mapped group -> denied.
		{[]string{"some-other-group"}, "", false},
		{nil, "", false},
	}
	for _, c := range cases {
		got, ok := MapGroupsToRole(c.groups, rm)
		if ok != c.ok || got != c.want {
			t.Errorf("MapGroupsToRole(%v) = (%q,%v), want (%q,%v)", c.groups, got, ok, c.want, c.ok)
		}
	}
}
