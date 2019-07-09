package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"

	"fmt"

	"path/filepath"

	"io/ioutil"

	"os"

	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/caddyserver/caddy"
)

type cookieManager struct {
	sc *securecookie.SecureCookie
}

func getCookie(given string) (*cookieManager, error) {
	var hashKey, blockKey []byte
	//given in caddyfile
	if len(given) > 0 {
		if len(given) < 10 {
			return nil, fmt.Errorf("cookie_secret is too short")
		}
		hashKey, blockKey = getKeys(given)
	} else {
		//ok, lets make one and store it in the .caddy dir then
		dir := filepath.Join(caddy.AssetsPath(), "oauth")
		if err := os.MkdirAll(dir, 0600); err != nil {
			return nil, err
		}
		fpath := filepath.Join(dir, "secret.key")
		dat, err := ioutil.ReadFile(fpath)
		//not there. make it.
		if os.IsNotExist(err) {
			dat = make([]byte, 64)
			rand.Read(dat)
			err = ioutil.WriteFile(fpath, dat, 0600)
			if err != nil {
				return nil, fmt.Errorf("writing cookie_secret: %s", err)
			}
		} else if err != nil {
			return nil, err
		}
		if len(dat) != 64 {
			return nil, fmt.Errorf("Stored cookie_secret is wrong length. Expect exactly 64 bytes")
		}
		hashKey, blockKey = dat[:32], dat[32:]
	}
	return &cookieManager{sc: securecookie.New(hashKey, blockKey)}, nil
}

func getKeys(s string) ([]byte, []byte) {
	var dat []byte
	var err error
	//if valid b64, use that. best practice is a 64 byte random base 64 string
	if dat, err = base64.StdEncoding.DecodeString(s); err != nil {
		dat = []byte(s)
	}
	var hashKey, blockKey []byte
	//exactly 64 bytes, awesome
	if len(dat) == 64 {
		hashKey, blockKey = dat[:32], dat[32:]
	} else {
		//otherwise hash each half
		split := len(dat) / 2
		h, e := sha256.Sum256(dat[split:]), sha256.Sum256(dat[:split])
		hashKey, blockKey = h[:], e[:]
	}
	return hashKey, blockKey
}

func (cm *cookieManager) ReadCookie(r *http.Request, name string, maxAge int, dst interface{}) error {
	val, err := cm.ReadCookiePlain(r, name)
	if err != nil {
		return err
	}
	if err = cm.sc.MaxAge(maxAge).Decode(name, val, dst); err != nil {
		return err
	}
	return nil
}

func (cm *cookieManager) SetCookie(w http.ResponseWriter, name string, maxAge int, dat interface{}) error {
	val, err := cm.sc.MaxAge(maxAge).Encode(name, dat)
	if err != nil {
		return err
	}
	cm.SetCookiePlain(w, name, maxAge, val)
	return nil
}

func (cm *cookieManager) SetCookiePlain(w http.ResponseWriter, name string, maxAge int, value string) {
	cookie := &http.Cookie{
		MaxAge:   maxAge,
		HttpOnly: true,
		Name:     name,
		Path:     "/",
		Secure:   true,
		Value:    value,
	}
	http.SetCookie(w, cookie)
}

func (cm *cookieManager) ReadCookiePlain(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err //cookie no exist
	}
	return cookie.Value, nil
}

func (cm *cookieManager) ClearCookie(w http.ResponseWriter, name string) {
	cm.SetCookiePlain(w, name, -1, "")
}
