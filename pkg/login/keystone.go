package login

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/keystone"
	"github.com/grafana/grafana/pkg/log"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"net/http"
)

type keystoneAuther struct {
	server         string
	v3             bool
	userdomainname string
	token          string
	tenants        []keystone.V2_tenant_struct
	v3token        keystone.V3_auth_response_struct
	userId         string
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
	var auth_post keystone.V2_auth_post_struct
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
	var auth_response keystone.V2_auth_response_struct
	err = decoder.Decode(&auth_response)
	if err != nil {
		return err
	}

	a.token = auth_response.Access.Token.ID
	a.userId = auth_response.Access.User.ID

	return nil
}

func (a *keystoneAuther) authenticateV3(username, password string) error {
	var auth_post keystone.V3_auth_post_struct
	auth_post.Auth.Identity.Methods = []string{"password"}
	auth_post.Auth.Identity.Password.User.Name = username
	auth_post.Auth.Identity.Password.User.Password = password
	// the user domain name is currently hardcoded via a config setting - this should change to an extra domain field in the login dialog later
	auth_post.Auth.Identity.Password.User.Domain.Name = a.userdomainname
	b, _ := json.Marshal(auth_post)

	request, err := http.NewRequest("POST", a.server+"/v3/auth/tokens?nocatalog", bytes.NewBuffer(b))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json")

	resp, err := keystone.GetHttpClient().Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return errors.New("Keystone authentication failed: " + resp.Status)
	}

	// in keystone v3 the token is in the response header
	a.token = resp.Header.Get("X-Subject-Token")

	// parse the token body - we'll be using the roles later
	err = json.NewDecoder(resp.Body).Decode(&a.v3token)
	if err != nil {
		return err
	}
	a.userId = a.v3token.Token.User.ID
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

			keystoneRole, err := a.roleMappedFromKeystone(tenant)
			if err != nil {
				return err
			}

			// If we get a configured role, use it - otherwise leave it as Editor
			if keystoneRole != "" {
				roleName = keystoneRole
				log.Info("Org '%s': use role mapped from keystone: %s", grafanaOrg.Name, roleName)
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

func (a *keystoneAuther) roleMappedFromKeystone(tenant keystone.V2_tenant_struct) (string, error) {
	keystoneRoles, err := a.getTenantRoles(a.userId, tenant)
	if err != nil {
		return "", err
	}

	// Check most privileged roles first
	if contains(setting.KeystoneAdminRoles, keystoneRoles) {
		return "Admin", nil
	}
	if contains(setting.KeystoneEditorRoles, keystoneRoles) {
		return "Editor", nil
	}
	if contains(setting.KeystoneEditorReadonlyRoles, keystoneRoles) {
		return "EditorReadonly", nil
	}
	if contains(setting.KeystoneViewerRoles, keystoneRoles) {
		return "Viewer", nil
	}
	// If nothing matches, return the default role
	return setting.KeystoneDefaultRole, nil
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

func (a *keystoneAuther) getTenantRoles(userId string, tenant keystone.V2_tenant_struct) ([]string, error) {
	if a.v3 {
		return a.getProjectRolesV3(userId, tenant)
	} else {
		return a.getTenantRolesV2(userId, tenant)
	}
}

/*
Get project roles by re-authenticating with project scope, using existing domain-scoped token
*/
func (a *keystoneAuther) getProjectRolesV3(userId string, tenant keystone.V2_tenant_struct) ([]string, error) {
	var auth_post keystone.V3_auth_post_struct
	auth_post.Auth.Identity.Methods = []string{"token"}
	auth_post.Auth.Identity.Token = &keystone.V3_token_struct{ID: a.token}
	auth_post.Auth.Scope = &keystone.V3_auth_scope_struct{Project: keystone.V3_project_struct{ID: tenant.ID}}
	b, _ := json.Marshal(auth_post)

	request, err := http.NewRequest("POST", a.server+"/v3/auth/tokens?nocatalog", bytes.NewBuffer(b))
	if err != nil {
		return []string{}, err
	}
	request.Header.Add("Content-Type", "application/json")

	resp, err := keystone.GetHttpClient().Do(request)
	if err != nil {
		return []string{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		return []string{}, errors.New("Keystone project-scoped authentication failed: " + resp.Status)
	}

	var v3token keystone.V3_auth_response_struct
	err = json.NewDecoder(resp.Body).Decode(&v3token)
	if err != nil {
		return []string{}, err
	}
	var keystoneRoles []string

	for _, tokenRole := range v3token.Token.Roles {
		keystoneRoles = append(keystoneRoles, tokenRole.Name)
	}

	log.Info("Roles from token for project '%s': %v", tenant.Name, keystoneRoles)

	return keystoneRoles, nil
}

/*
Get tenant roles by re-authenticating with tenant scope, using existing global-scoped token
*/
func (a *keystoneAuther) getTenantRolesV2(userId string, tenant keystone.V2_tenant_struct) ([]string, error) {
	var auth_post keystone.V2_auth_post_struct
	auth_post.Auth.Token = &keystone.V2_token_struct{ID: a.token}
	auth_post.Auth.TenantID = tenant.ID
	b, _ := json.Marshal(auth_post)

	request, err := http.NewRequest("POST", a.server+"/v2.0/tokens", bytes.NewBuffer(b))
	if err != nil {
		return []string{}, err
	}
	request.Header.Add("Content-Type", "application/json")

	resp, err := keystone.GetHttpClient().Do(request)
	if err != nil {
		return []string{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 203 {
		return []string{}, errors.New("Keystone tenant-scoped authentication failed: " + resp.Status)
	}

	var v2response keystone.V2_auth_response_struct
	err = json.NewDecoder(resp.Body).Decode(&v2response)
	if err != nil {
		return []string{}, err
	}
	var keystoneRoles []string

	for _, tokenRole := range v2response.Access.User.Roles {
		keystoneRoles = append(keystoneRoles, tokenRole.Name)
	}

	log.Info("Roles from token for tenant '%s': %v", tenant.Name, keystoneRoles)

	return keystoneRoles, nil
}

func (a *keystoneAuther) getTenantList() error {
	if a.v3 {
		return a.getProjectListV3()
	} else {
		return a.getTenantListV2()
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
	var tenant_response keystone.V2_tenant_response_struct
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
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New("Keystone project-list failed: " + resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	var project_response keystone.V3_project_response_struct
	err = decoder.Decode(&project_response)
	if err != nil {
		return err
	}

	tenants := []keystone.V2_tenant_struct{}
	for _, project := range project_response.Projects {
		tenants = append(tenants, keystone.V2_tenant_struct{Name: project.Name, ID: project.ID})
	}
	a.tenants = tenants
	return nil
}
