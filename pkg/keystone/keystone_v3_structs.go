package keystone

import (
	"time"
)

type V3_auth_post_struct struct {
	Auth struct {
		Identity struct {
			Methods  []string `json:"methods"`
			Password struct {
				User struct {
					Name     string `json:"name"`
					Password string `json:"password"`
					Domain   struct {
						Name string `json:"name"`
					} `json:"domain"`
				} `json:"user"`
			} `json:"password"`
			Token *V3_token_struct `json:"token,omitempty"`
		} `json:"identity"`
		Scope struct {
			Project *V3_project_struct `json:"project,omitempty"`
		} `json:"scope"`
	} `json:"auth"`
}

type V3_project_struct struct {
	ID     string            `json:"id,omitempty"`
	Name   string            `json:"name,omitempty"`
	Domain *V3_domain_struct `json:"project,omitempty"`
}

type V3_domain_struct struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type V3_token_struct struct {
	ID string `json:"id,omitempty"`
}

type V3_project_response_struct struct {
	Projects []struct {
		Description interface{} `json:"description"`
		Enabled     bool        `json:"enabled"`
		ID          string      `json:"id"`
		Name        string      `json:"name"`
	} `json:"projects"`
}

type V3_auth_response_struct struct {
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

type V3_role_assignment_struct struct {
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

type V3_role_struct struct {
	Role struct {
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Name string `json:"name"`
	} `json:"role"`
}
