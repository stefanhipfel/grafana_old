package keystone

import (
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/log"
	"github.com/grafana/grafana/pkg/middleware"
	m "github.com/grafana/grafana/pkg/models"
	"github.com/grafana/grafana/pkg/setting"
	"io"
	"strings"
)

const (
	SESS_TOKEN            = "keystone_token"
	SESS_TOKEN_EXPIRATION = "keystone_expiration"
	SESS_TOKEN_PROJECT    = "keystone_project"
	TOKEN_BUFFER_TIME     = 5 // Tokens refresh if the token will expire in less than this many minutes
)

func getUserName(c *middleware.Context) (string, error) {
	var keystoneUserIdObj interface{}
	if setting.KeystoneCookieCredentials {
		if keystoneUserIdObj = c.GetCookie(setting.CookieUserName); keystoneUserIdObj == nil {
			return "", errors.New("Couldn't find cookie containing keystone userId")
		} else {
			return keystoneUserIdObj.(string), nil
		}
	} else if keystoneUserIdObj = c.Session.Get(middleware.SESS_KEY_USERID); keystoneUserIdObj == nil {
		return "", errors.New("Session timed out trying to get keystone userId")
	}

	userQuery := m.GetUserByIdQuery{Id: keystoneUserIdObj.(int64)}
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

func getNewToken(c *middleware.Context) (string, error) {
	var username, project string
	var err error
	if username, err = getUserName(c); err != nil {
		return "", err
	}
	if project, err = getOrgName(c); err != nil {
		return "", err
	}

	var keystonePasswordObj interface{}
	if setting.KeystoneCookieCredentials {
		if keystonePasswordObj = c.GetCookie(middleware.SESS_KEY_PASSWORD); keystonePasswordObj == nil {
			return "", errors.New("Couldn't find cookie containing keystone password")
		} else {
			log.Debug("Got password from cookie")
		}
	} else if keystonePasswordObj = c.Session.Get(middleware.SESS_KEY_PASSWORD); keystonePasswordObj == nil {
		return "", errors.New("Session timed out trying to get keystone password")
	} else if keystonePasswordObj != nil {
		log.Debug("Got password from session")
	}

	if setting.KeystoneCredentialAesKey != "" {
		keystonePasswordObj = decryptPassword(keystonePasswordObj.(string))
		log.Debug("Decrypted password")
	} else {
		log.Warn("Password stored in cleartext!")
	}

	user, domain := UserDomain(username)
	keystoneProject := strings.Replace(project, "@"+domain, "", 1)
	auth := Auth_data{
		Username: user,
		Project:  keystoneProject,
		Password: keystonePasswordObj.(string),
		Domain:   domain,
		Server:   setting.KeystoneURL,
	}
	if err := AuthenticateScoped(&auth); err != nil {
		c.SetCookie(setting.CookieUserName, "", -1, setting.AppSubUrl+"/", nil, middleware.IsSecure(c), true)
		c.SetCookie(setting.CookieRememberName, "", -1, setting.AppSubUrl+"/", nil, middleware.IsSecure(c), true)
		c.SetCookie(middleware.SESS_KEY_PASSWORD, "", -1, setting.AppSubUrl+"/", nil, middleware.IsSecure(c), true)
		c.Session.Destory(c)
		return "", err
	}

	c.Session.Set(SESS_TOKEN, auth.Token)
	c.Session.Set(SESS_TOKEN_EXPIRATION, auth.Expiration)
	c.Session.Set(SESS_TOKEN_PROJECT, project)
	// in keystone v3 the token is in the response header
	return auth.Token, nil
}

func validateCurrentToken(c *middleware.Context) (bool, error) {
	token := c.Session.Get(SESS_TOKEN)
	if token == nil {
		return false, nil
	}

	expiration_obj := c.Session.Get(SESS_TOKEN_EXPIRATION)
	if expiration_obj == nil || expiration_obj.(string) == "" {
		return false, nil
	}
	expiration, err := time.Parse(time.RFC3339, expiration_obj.(string))
	if err != nil {
		return false, err
	}

	now := time.Now()
	if now.After(expiration.Add(-TOKEN_BUFFER_TIME * time.Minute)) {
		return false, nil
	}

	project := c.Session.Get(SESS_TOKEN_PROJECT)
	org, err := getOrgName(c)
	if err != nil {
		return false, err
	}
	if org != project {
		return false, nil
	}

	return true, nil
}

func GetToken(c *middleware.Context) (string, error) {
	var token string
	var err error
	valid, err := validateCurrentToken(c)
	if valid {

		var sessionTokenObj interface{}
		if sessionTokenObj = c.Session.Get(SESS_TOKEN); sessionTokenObj == nil {
			return "", errors.New("Session timed out trying to get token")
		}
		return sessionTokenObj.(string), nil
	}
	if token, err = getNewToken(c); err != nil {
		return "", err
	}
	return token, nil
}

func EncryptPassword(password string) string {
	key := []byte(setting.KeystoneCredentialAesKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error(3, "Error: NewCipher(%d bytes) = %s", len(setting.KeystoneCredentialAesKey), err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(password))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		log.Error(3, "Error: %s", err)
	}
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(password))

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func decryptPassword(base64ciphertext string) string {
	key := []byte(setting.KeystoneCredentialAesKey)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error(3, "Error: NewCipher(%d bytes) = %s", len(setting.KeystoneCredentialAesKey), err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(base64ciphertext)
	if err != nil {
		log.Error(3, "Error: %s", err)
		return ""
	}
	iv := ciphertext[:aes.BlockSize]
	if aes.BlockSize > len(ciphertext) {
		log.Error(3, "Error: ciphertext %s is shorter than AES blocksize %d", ciphertext, aes.BlockSize)
		return ""
	}
	password := make([]byte, len(ciphertext)-aes.BlockSize)
	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(password, ciphertext[aes.BlockSize:])
	return string(password)
}

func UserDomain(username string) (string, string) {
	user := username
	domain := setting.KeystoneDefaultDomain
	if at_idx := strings.IndexRune(username, '@'); at_idx > 0 {
		domain = username[at_idx+1:]
		user = username[:at_idx]
	}
	return user, domain
}
