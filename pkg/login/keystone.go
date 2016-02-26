package login

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/grafana/grafana/pkg/api/keystone"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
)

type keystoneAuther struct {
	server         string
	v3             bool
	userdomainname string
	token          string
	tenants        []tenant_struct
	v3token        V3Token
}

type V3Token struct {
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

type v2_auth_response_struct struct {
	Access v2_access_struct
}

type v2_access_struct struct {
	Token v2_token_struct
}

type v2_token_struct struct {
	Id string
}

type v2_auth_post_struct struct {
	Auth v2_auth_struct `json:"auth"`
}

type v2_auth_struct struct {
	PasswordCredentials v2_credentials_struct `json:"passwordCredentials"`
}

type v2_credentials_struct struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type v2_tenant_response_struct struct {
	Tenants []tenant_struct
}

type tenant_struct struct {
	Name string
}

type v3_auth_post_struct struct {
	Auth v3_auth_struct `json:"auth"`
}

type v3_auth_struct struct {
	Identity v3_identity_struct `json:"identity"`
}

type v3_identity_struct struct {
	Methods  []string                 `json:"methods"`
	Password v3_passwordmethod_struct `json:"password"`
}

type v3_passwordmethod_struct struct {
	User v3_user_struct `json:"user"`
}

type v3_user_struct struct {
	Name     string               `json:"name"`
	Password string               `json:"password"`
	Domain   v3_userdomain_struct `json:"domain"`
}

type v3_userdomain_struct struct {
	Name string `json:"name"`
}

type v3_project_response_struct struct {
	Projects []tenant_struct
}

func NewKeystoneAuthenticator(server string, v3 bool, userdomainaname string) *keystoneAuther {
	return &keystoneAuther{server: server, v3: v3, userdomainname: userdomainaname}
}

func (a *keystoneAuther) login(query *LoginUserQuery) error {

	// perform initial authentication
	if err := a.authenticate(query.Username, query.Password); err != nil {
		return err
	}

	if grafanaUser, err := a.getGrafanaUserFor(query.Username); err != nil {
		return err
	} else {
		// sync org roles
		if err := a.syncOrgRoles(grafanaUser); err != nil {
			return err
		}
		query.User = grafanaUser
		return nil
	}

}

func (a *keystoneAuther) authenticate(username, password string) error {
	if a.v3 {
		if err := a.authenticateV3(username, password); err != nil {
			return err
		}
	} else {
		if err := a.authenticateV2(username, password); err != nil {
			return err
		}
	}
	return nil
}

func (a *keystoneAuther) authenticateV2(username, password string) error {
	var auth_post v2_auth_post_struct
	auth_post.Auth.PasswordCredentials.Username = username
	auth_post.Auth.PasswordCredentials.Password = password
	b, _ := json.Marshal(auth_post)

	request, err := http.NewRequest("POST", a.server+"/v2.0/tokens", bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	} else if resp.StatusCode != 200 {
		return errors.New("Keystone authentication failed: " + resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	var auth_response v2_auth_response_struct
	err = decoder.Decode(&auth_response)
	if err != nil {
		return err
	}

	a.token = auth_response.Access.Token.Id
	return nil
}

func (a *keystoneAuther) authenticateV3(username, password string) error {
	var auth_post v3_auth_post_struct
	auth_post.Auth.Identity.Methods = []string{"password"}
	auth_post.Auth.Identity.Password.User.Name = username
	auth_post.Auth.Identity.Password.User.Password = password
	// the user domain name is currently hardcoded via a config setting - this should change to an extra domain field in the login dialog later
	auth_post.Auth.Identity.Password.User.Domain.Name = a.userdomainname
	b, _ := json.Marshal(auth_post)

	request, err := http.NewRequest("POST", a.server+"/v3/auth/tokens", bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json")

	resp, err := keystone.GetHttpClient().Do(request)
	if err != nil {
		return err
	} else if resp.StatusCode != 201 {
		return errors.New("Keystone authentication failed: " + resp.Status)
	}

	// in keystone v3 the token is in the response header
	a.token = resp.Header.Get("X-Subject-Token")

	// parse the token body - we'll be using the roles later
	err = json.NewDecoder(resp.Body).Decode(&a.v3token)
	if err != nil {
		return err
	}
	return nil
}

func (a *keystoneAuther) getGrafanaUserFor(username string) (*m.User, error) {
	// get user from grafana db
	userQuery := m.GetUserByLoginQuery{LoginOrEmail: username}
	if err := bus.Dispatch(&userQuery); err != nil {
		if err == m.ErrUserNotFound {
			return a.createGrafanaUser(username)
		} else {
			return nil, err
		}
	}

	return userQuery.Result, nil
}

func (a *keystoneAuther) createGrafanaUser(username string) (*m.User, error) {
	cmd := m.CreateUserCommand{
		Login: username,
	}

	if err := bus.Dispatch(&cmd); err != nil {
		return nil, err
	}

	return &cmd.Result, nil
}

func (a *keystoneAuther) getGrafanaOrgFor(orgname string) (*m.Org, error) {
	// get org from grafana db
	orgQuery := m.GetOrgByNameQuery{Name: orgname}
	if err := bus.Dispatch(&orgQuery); err != nil {
		if err == m.ErrOrgNotFound {
			return a.createGrafanaOrg(orgname)
		} else {
			return nil, err
		}
	}

	return orgQuery.Result, nil
}

func (a *keystoneAuther) createGrafanaOrg(orgname string) (*m.Org, error) {
	cmd := m.CreateOrgCommand{
		Name: orgname,
	}

	if err := bus.Dispatch(&cmd); err != nil {
		return nil, err
	}

	return &cmd.Result, nil
}

func (a *keystoneAuther) syncOrgRoles(user *m.User) error {
	err := a.getTenantList()
	if err != nil {
		return err
	}

	orgsQuery := m.GetUserOrgListQuery{UserId: user.Id}
	if err := bus.Dispatch(&orgsQuery); err != nil {
		return err
	}

	handledOrgIds := map[int64]bool{}

	// update or remove org roles
	for _, org := range orgsQuery.Result {
		match := false
		handledOrgIds[org.OrgId] = true

		// search for matching tenant
		for _, tenant := range a.tenants {
			if org.Name == tenant.Name {
				match = true
				break
			}
		}

		// remove role if no tenant mappings match
		if !match {
			cmd := m.RemoveOrgUserCommand{OrgId: org.OrgId, UserId: user.Id}
			if err := bus.Dispatch(&cmd); err != nil {
				// Ignore remove org user if user is the last admin
				if err != m.ErrLastOrgAdmin {
					return err
				}
			}
		}
	}

	// add missing org roles
	for _, tenant := range a.tenants {

		if grafanaOrg, err := a.getGrafanaOrgFor(tenant.Name); err != nil {
			return err
		} else {
			var exists bool
			if _, exists = handledOrgIds[grafanaOrg.Id]; exists {
				if !a.keystoneRoleMappingsConfigured() {
					continue
				}
			}
			// add role
			roleName := "Editor"

			keystoneRole := a.roleMappedFromKeystone()
			log.Info("Mapped role: %v", keystoneRole)
			// If we get a configured role, use it - otherwise leave it as Editor
			if keystoneRole != "" {
				roleName = keystoneRole
			}

			if exists {
				cmd := m.UpdateOrgUserCommand{UserId: user.Id, Role: m.RoleType(roleName), OrgId: grafanaOrg.Id}
				if err := bus.Dispatch(&cmd); err != nil {
					return err
				}
			} else {
				cmd := m.AddOrgUserCommand{UserId: user.Id, Role: m.RoleType(roleName), OrgId: grafanaOrg.Id}
				if err := bus.Dispatch(&cmd); err != nil {
					return err
				}
			}

			// set org if none is set (for new users)
			if user.OrgId == 1 {
				cmd := m.SetUsingOrgCommand{UserId: user.Id, OrgId: grafanaOrg.Id}
				if err := bus.Dispatch(&cmd); err != nil {
					return err
				}
			}

			// mark this tenant has handled so we do not process it again
			handledOrgIds[grafanaOrg.Id] = true
		}
	}

	return nil
}

func (a *keystoneAuther) keystoneRoleMappingsConfigured() bool {
	return len(setting.KeystoneViewerRoles) != 0 ||
		len(setting.KeystoneEditorReadonlyRoles) != 0 ||
		len(setting.KeystoneEditorRoles) != 0 ||
		len(setting.KeystoneAdminRoles) != 0 ||
		setting.KeystoneDefaultRole != ""
}

func (a *keystoneAuther) roleMappedFromKeystone() string {
	var keystoneRoles []string

	for _, tokenRole := range a.v3token.Token.Roles {
		keystoneRoles = append(keystoneRoles, tokenRole.Name)
	}

	log.Info("Roles from token: %v", keystoneRoles)

	// Check most privileged roles first
	if contains(setting.KeystoneAdminRoles, keystoneRoles) {
		return "Admin"
	}
	if contains(setting.KeystoneEditorRoles, keystoneRoles) {
		return "Editor"
	}
	if contains(setting.KeystoneEditorReadonlyRoles, keystoneRoles) {
		return "EditorReadonly"
	}
	if contains(setting.KeystoneViewerRoles, keystoneRoles) {
		return "Viewer"
	}
	// If nothing matches, return the default role
	return setting.KeystoneDefaultRole
}

func contains(configuredRoles, keystoneRoles []string) bool {
	for _, keystoneRole := range keystoneRoles {
		for _, configuredRole := range configuredRoles {
			if keystoneRole == configuredRole {
				return true
			}
		}
	}
	return false
}

func (a *keystoneAuther) getTenantList() error {
	if a.v3 {
		if err := a.getProjectListV3(); err != nil {
			return err
		}
	} else {
		if err := a.getTenantListV2(); err != nil {
			return err
		}
	}
	return nil
}

func (a *keystoneAuther) getTenantListV2() error {
	request, err := http.NewRequest("GET", a.server+"/v2.0/tenants", nil)
	if err != nil {
		return err
	}
	request.Header.Add("X-Auth-Token", a.token)

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	} else if resp.StatusCode != 200 {
		return errors.New("Keystone tenant-list failed: " + resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	var tenant_response v2_tenant_response_struct
	err = decoder.Decode(&tenant_response)
	if err != nil {
		return err
	}
	a.tenants = tenant_response.Tenants
	return nil
}

func (a *keystoneAuther) getProjectListV3() error {
	request, err := http.NewRequest("GET", a.server+"/v3/auth/projects", nil)
	if err != nil {
		return err
	}
	request.Header.Add("X-Auth-Token", a.token)

	resp, err := keystone.GetHttpClient().Do(request)
	if err != nil {
		return err
	} else if resp.StatusCode != 200 {
		return errors.New("Keystone project-list failed: " + resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	var project_response v3_project_response_struct
	err = decoder.Decode(&project_response)
	if err != nil {
		return err
	}
	a.tenants = project_response.Projects
	return nil
}
