package keystone

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/keystone"
	"github.com/grafana/grafana/pkg/middleware"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
)

func getUserName(c *middleware.Context) (string, error) {
	userQuery := m.GetUserByIdQuery{Id: c.Session.Get(middleware.SESS_KEY_USERID).(int64)}
	if err := bus.Dispatch(&userQuery); err != nil {
		if err == m.ErrUserNotFound {
			return "", err
		}
	}
	return userQuery.Result.Login, nil
}

func getOrgName(c *middleware.Context) (string, error) {
	orgQuery := m.GetOrgByIdQuery{Id: c.OrgId}
	if err := bus.Dispatch(&orgQuery); err != nil {
		if err == m.ErrOrgNotFound {
			return "", err
		}
	}
	return orgQuery.Result.Name, nil
}

func authenticateV2(c *middleware.Context) (string, error) {
	server := setting.KeystoneURL

	var auth_post keystone.V2_auth_post_struct
	if username, err := getUserName(c); err != nil {
		return "", err
	} else {
		auth_post.Auth.PasswordCredentials.Username = username
	}
	if tenant, err := getOrgName(c); err != nil {
		return "", err
	} else {
		auth_post.Auth.TenantName = tenant
	}
	auth_post.Auth.PasswordCredentials.Password = c.Session.Get(middleware.SESS_KEY_PASSWORD).(string)
	b, _ := json.Marshal(auth_post)

	request, err := http.NewRequest("POST", server+"/v2.0/tokens", bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}

	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return "", err
	} else if resp.StatusCode != 200 {
		return "", errors.New("Keystone authentication failed: " + resp.Status)
	}

	decoder := json.NewDecoder(resp.Body)
	var auth_response keystone.V2_auth_response_struct
	err = decoder.Decode(&auth_response)
	if err != nil {
		return "", err
	}

	return auth_response.Access.Token.ID, nil
}

func authenticateV3(c *middleware.Context) (string, error) {
	server := setting.KeystoneURL

	var auth_post keystone.V3_auth_post_struct
	auth_post.Auth.Identity.Methods = []string{"password"}
	if username, err := getUserName(c); err != nil {
		return "", err
	} else {
		auth_post.Auth.Identity.Password.User.Name = username
	}
	auth_post.Auth.Scope = &keystone.V3_auth_scope_struct{}
	if tenant, err := getOrgName(c); err != nil {
		return "", err
	} else {
		auth_post.Auth.Scope.Project = keystone.V3_project_struct{Name: tenant}
	}
	auth_post.Auth.Identity.Password.User.Password = c.Session.Get(middleware.SESS_KEY_PASSWORD).(string)
	// the user domain name is currently hardcoded via a config setting - this should change to an extra domain field in the login dialog later
	auth_post.Auth.Identity.Password.User.Domain.Name = setting.KeystoneUserDomainName
	// set the project domain name to the user domain name, as we only deal with the projects for the domain the user logged in with
	auth_post.Auth.Scope.Project.Domain = &keystone.V3_domain_struct{Name: setting.KeystoneUserDomainName}
	b, _ := json.Marshal(auth_post)

	request, err := http.NewRequest("POST", server+"/v3/auth/tokens?nocatalog", bytes.NewBuffer(b))
	if err != nil {
		return "", err
	}
	request.Header.Add("Content-Type", "application/json")

	resp, err := keystone.GetHttpClient().Do(request)
	if err != nil {
		return "", err
	} else if resp.StatusCode != 201 {
		return "", errors.New("Keystone authentication failed: " + resp.Status)
	}

	// in keystone v3 the token is in the response header
	return resp.Header.Get("X-Subject-Token"), nil
}

func GetToken(c *middleware.Context) (string, error) {
	var token string
	var err error
	if setting.KeystoneV3 {
		if token, err = authenticateV3(c); err != nil {
			return "", err
		}
	} else {
		if token, err = authenticateV2(c); err != nil {
			return "", err
		}
	}
	return token, nil
}
