// Package wsse - HTTP-хендлеры /wsse/sign, /wsse/verify (аналог
// kz.ncanode.service.WsseService).
package wsse

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/certservice"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
	"github.com/ncanode-kz/gokalkan"
)

func RegisterRoutes(s *httpapi.Server, a *app.App) {
	httpapi.Handle(s, "POST /wsse/sign", func(r *http.Request, req dto.WsseSignRequest) (dto.XmlSignResponse, error) {
		return sign(a, req)
	})
	httpapi.Handle(s, "POST /wsse/verify", func(r *http.Request, req dto.XmlVerifyRequest) (dto.VerificationResponse, error) {
		return verify(a, req.XML, req.HasOCSP(), req.HasCRL())
	})
}

func sign(a *app.App, req dto.WsseSignRequest) (dto.XmlSignResponse, error) {
	if req.Key == "" {
		return dto.XmlSignResponse{}, httpapi.ClientError("key is required", nil)
	}

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	if _, err := kalkanutil.LoadSigner(a.Shared, req.Key, req.Password); err != nil {
		return dto.XmlSignResponse{}, httpapi.ServerError("failed to load signer", err)
	}

	xmlData := req.XML
	if req.TrimXML {
		trimmed, err := gokalkan.TrimXML(xmlData)
		if err != nil {
			return dto.XmlSignResponse{}, httpapi.ClientError("failed to trim xml", err)
		}
		xmlData = trimmed
	}

	signed, err := a.Shared.SignWSSE(xmlData, randomID())
	if err != nil {
		return dto.XmlSignResponse{}, httpapi.ServerError("failed to sign", err)
	}

	return dto.XmlSignResponse{StatusResponse: dto.OK(), XML: signed}, nil
}

// verify реализует /wsse/verify. Как и Java (WsseService.verify), проверяет
// и возвращает только ОДНОГО (первого) подписанта, даже если в конверте
// несколько ds:Signature - формат WSSE/SmartBridge подразумевает одну подпись.
func verify(a *app.App, xmlData string, checkOCSP, checkCRL bool) (dto.VerificationResponse, error) {
	_, verifyErr := a.Shared.VerifyWSSE(xmlData)
	if verifyErr != nil {
		return dto.VerificationResponse{StatusResponse: dto.OK(), Valid: false}, nil
	}

	certDER, err := a.Shared.GetCertFromXML(xmlData, 1)
	if err != nil || len(certDER) == 0 {
		return dto.VerificationResponse{StatusResponse: dto.OK(), Valid: false}, nil
	}

	certInfo, err := certservice.Build(a.Shared, a.CRL, kalkanutil.PEMFromBase64Body(certDER), checkOCSP, checkCRL)
	if err != nil {
		return dto.VerificationResponse{}, httpapi.ServerError("failed to build certificate info", err)
	}

	return dto.VerificationResponse{
		StatusResponse: dto.OK(),
		Valid:          certInfo.Valid,
		Signers:        []*dto.CertificateInfo{&certInfo},
	}, nil
}

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "id-" + hex.EncodeToString(b)
}
