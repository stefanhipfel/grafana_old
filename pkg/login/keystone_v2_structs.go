package login

import (
	"time"
)

type v2_auth_response_struct struct {
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
