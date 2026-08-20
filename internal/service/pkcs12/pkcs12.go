// Package pkcs12 - HTTP-хендлеры /pkcs12/info, /pkcs12/aliases (аналог
// kz.ncanode.controller.Pkcs12Controller).
package pkcs12

import (
	"fmt"
	"net/http"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/certservice"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
)

func RegisterRoutes(s *httpapi.Server, a *app.App) {
	httpapi.Handle(s, "POST /pkcs12/info", func(r *http.Request, req dto.Pkcs12InfoRequest) (dto.VerificationResponse, error) {
		return info(a, req)
	})
	httpapi.Handle(s, "POST /pkcs12/aliases", func(r *http.Request, req dto.Pkcs12InfoRequest) (dto.Pkcs12AliasesResponse, error) {
		return aliases(a, req)
	})
}

// info реализует /pkcs12/info. В отличие от /x509/info, здесь Java не
// продолжает обработку после ошибки загрузки одного из ключей (KeyStore
// bad password/corrupt PKCS12 и т.п.) - весь запрос падает как ServerException.
func info(a *app.App, req dto.Pkcs12InfoRequest) (dto.VerificationResponse, error) {
	if len(req.Keys) == 0 {
		return dto.VerificationResponse{}, httpapi.ClientError("keys must not be empty", nil)
	}

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	valid := true
	signers := make([]*dto.CertificateInfo, 0, len(req.Keys))

	for i, key := range req.Keys {
		certPEM, err := kalkanutil.LoadSigner(a.Shared, key.Key, key.Password, key.KeyAlias)
		if err != nil {
			return dto.VerificationResponse{}, httpapi.ServerError(fmt.Sprintf("failed to load key #%d", i), err)
		}

		certInfo, err := certservice.Build(a.Shared, a.CRL, certPEM, req.HasOCSP(), req.HasCRL())
		if err != nil {
			return dto.VerificationResponse{}, httpapi.ServerError(fmt.Sprintf("failed to inspect key #%d", i), err)
		}

		if !certInfo.Valid {
			valid = false
		}

		signers = append(signers, &certInfo)
	}

	return dto.VerificationResponse{StatusResponse: dto.OK(), Valid: valid, Signers: signers}, nil
}

// aliases реализует /pkcs12/aliases через KC_GetCertificatesList (см.
// gokalkan.Client.ListCertificateAliases). Эмпирически подтверждено (см.
// README): для хранилища, загруженного из PKCS12, эта функция нативной
// библиотеки возвращает ошибку KCR_NOTOKENFOUND ("no token found") - она
// работает только для аппаратных токенов (KAZTOKEN/eToken/JaCarta и т.п.), с
// которыми и была задумана (см. пример в SDK, test.cpp). Для PKCS12 (основной
// случай в экосистеме pki.gov.kz) поэтому используется тот же фолбэк, что и
// раньше - единственный дефолтный алиас "".
func aliases(a *app.App, req dto.Pkcs12InfoRequest) (dto.Pkcs12AliasesResponse, error) {
	if len(req.Keys) == 0 {
		return dto.Pkcs12AliasesResponse{}, httpapi.ClientError("keys must not be empty", nil)
	}

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	result := make([][]string, 0, len(req.Keys))

	for i, key := range req.Keys {
		if _, err := kalkanutil.LoadSigner(a.Shared, key.Key, key.Password, key.KeyAlias); err != nil {
			return dto.Pkcs12AliasesResponse{}, httpapi.ServerError(fmt.Sprintf("failed to load key #%d", i), err)
		}

		keyAliases, err := a.Shared.ListCertificateAliases()
		if err != nil || len(keyAliases) == 0 {
			// KC_GetCertificatesList недоступна для PKCS12 (см. коммент выше) -
			// тот же дефолтный алиас "", что и раньше.
			keyAliases = []string{""}
		}

		result = append(result, keyAliases)
	}

	return dto.Pkcs12AliasesResponse{StatusResponse: dto.OK(), Aliases: result}, nil
}
