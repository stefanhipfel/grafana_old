package login

import (
	"time"
)

type v3_auth_response_struct struct {
	Token struct {
		Methods []string `json:"methods"`
		Roles   []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"roles"`
		ExpiresAt time.Time `json:"expires_at"`
		Project   struct {
			Domain struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"domain"`
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"project"`
		Catalog []struct {
			Endpoints []struct {
				RegionID  string `json:"region_id"`
				URL       string `json:"url"`
				Region    string `json:"region"`
				Interface string `json:"interface"`
				ID        string `json:"id"`
			} `json:"endpoints"`
			Type string `json:"type"`
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"catalog"`
		Extras struct {
		} `json:"extras"`
		User struct {
			Domain struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"domain"`
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"user"`
		AuditIds []string  `json:"audit_ids"`
		IssuedAt time.Time `json:"issued_at"`
	} `json:"token"`
}

type v3_role_assignment_struct struct {
	RoleAssignments []struct {
		Links struct {
			Assignment string `json:"assignment"`
		} `json:"links"`
		Role struct {
			ID string `json:"id"`
		} `json:"role"`
		Scope struct {
			Domain struct {
				ID string `json:"id"`
			} `json:"domain,omitempty"`
			Project struct {
				ID string `json:"id"`
			} `json:"project,omitempty"`
		} `json:"scope"`
		User struct {
			ID string `json:"id"`
		} `json:"user,omitempty"`
		Group struct {
			ID string `json:"id"`
		} `json:"group,omitempty"`
	} `json:"role_assignments"`
	Links struct {
		Self     string      `json:"self"`
		Previous interface{} `json:"previous"`
		Next     interface{} `json:"next"`
	} `json:"links"`
}

type v3_role_struct struct {
	Role struct {
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Name string `json:"name"`
	} `json:"role"`
}
