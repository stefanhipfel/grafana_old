package keystone

import (
	"time"
)

type V2_tenant_response_struct struct {
	Tenants []V2_tenant_struct `json:"tenants"`
}

type V2_tenant_struct struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type V2_auth_post_struct struct {
	Auth struct {
		PasswordCredentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"passwordCredentials"`
		Token      *V2_token_struct `json:"token,omitempty"`
		TenantName string           `json:"tenantName,omitempty"`
		TenantID   string           `json:"tenantId,omitempty"`
	} `json:"auth"`
}

type V2_token_struct struct {
	ID string `json:"id,omitempty"`
}

type V2_auth_response_struct struct {
	Access struct {
		Token struct {
			IssuedAt string    `json:"issued_at"`
			Expires  time.Time `json:"expires"`
			ID       string    `json:"id"`
			Tenant   struct {
				Description interface{} `json:"description"`
				Enabled     bool        `json:"enabled"`
				ID          string      `json:"id"`
				Name        string      `json:"name"`
			} `json:"tenant"`
		} `json:"token"`
		ServiceCatalog []struct {
			Endpoints []struct {
				AdminURL    string `json:"adminURL"`
				Region      string `json:"region"`
				InternalURL string `json:"internalURL"`
				ID          string `json:"id"`
				PublicURL   string `json:"publicURL"`
			} `json:"endpoints"`
			EndpointsLinks []interface{} `json:"endpoints_links"`
			Type           string        `json:"type"`
			Name           string        `json:"name"`
		} `json:"serviceCatalog"`
		User struct {
			Username   string        `json:"username"`
			RolesLinks []interface{} `json:"roles_links"`
			ID         string        `json:"id"`
			Roles      []struct {
				Name string `json:"name"`
			} `json:"roles"`
			Name string `json:"name"`
		} `json:"user"`
		Metadata struct {
			IsAdmin int      `json:"is_admin"`
			Roles   []string `json:"roles"`
		} `json:"metadata"`
		Trust struct {
			ID            string `json:"id"`
			TrusteeUserID string `json:"trustee_user_id"`
			TrustorUserID string `json:"trustor_user_id"`
			Impersonation bool   `json:"impersonation"`
		} `json:"trust"`
	} `json:"access"`
}
