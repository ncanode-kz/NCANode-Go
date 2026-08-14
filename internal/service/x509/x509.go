// Package x509 - HTTP-хендлеры /x509/info, /x509/sign, /x509/verify (аналог
// части kz.ncanode.service.CertificateService, вызываемой из X509Controller).
package x509

import (
	"encoding/base64"
	"net/http"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/certservice"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
)

func RegisterRoutes(s *httpapi.Server, a *app.App) {
	httpapi.Handle(s, "POST /x509/info", func(r *http.Request, req dto.X509InfoRequest) (dto.VerificationResponse, error) {
		return info(a, req)
	})
	httpapi.Handle(s, "POST /x509/sign", func(r *http.Request, req dto.SbaSignRequest) (dto.SbaSignResponse, error) {
		return sign(a, req)
	})
	httpapi.Handle(s, "POST /x509/verify", func(r *http.Request, req dto.SbaVerifyRequest) (dto.VerificationResponse, error) {
		return verify(a, req)
	})
}

// info реализует /x509/info: как и в Java, невалидный сертификат в батче не
// прерывает обработку остальных - на его месте в signers оказывается null,
// а весь ответ помечается valid=false. Пустой список certs тоже valid=false.
func info(a *app.App, req dto.X509InfoRequest) (dto.VerificationResponse, error) {
	valid := len(req.Certs) > 0

	signers := make([]*dto.CertificateInfo, 0, len(req.Certs))

	for _, certB64 := range req.Certs {
		der, err := base64.StdEncoding.DecodeString(kalkanutil.StripWhitespace(certB64))
		if err != nil {
			valid = false
			signers = append(signers, nil)
			continue
		}

		certInfo, err := certservice.Build(a.Shared, a.CRL, kalkanutil.PEMFromDER(der), req.HasOCSP(), req.HasCRL())
		if err != nil {
			valid = false
			signers = append(signers, nil)
			continue
		}

		if !certInfo.Valid {
			valid = false
		}

		signers = append(signers, &certInfo)
	}

	return dto.VerificationResponse{StatusResponse: dto.OK(), Valid: valid, Signers: signers}, nil
}

// sign реализует /x509/sign ("sign by algorithm" - сырая подпись
// произвольных данных, не CMS). data подписывается как есть, в виде байт
// UTF-8 строки - как и в Java (data.getBytes(UTF_8)), НЕ как base64.
func sign(a *app.App, req dto.SbaSignRequest) (dto.SbaSignResponse, error) {
	if req.Signer.Key == "" {
		return dto.SbaSignResponse{}, httpapi.ClientError("signer.key is required", nil)
	}

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	certPEM, err := kalkanutil.LoadSigner(a.Shared, req.Signer.Key, req.Signer.Password)
	if err != nil {
		return dto.SbaSignResponse{}, httpapi.ServerError("failed to load signer", err)
	}

	signature, err := a.Shared.SignRaw([]byte(req.Data))
	if err != nil {
		return dto.SbaSignResponse{}, httpapi.ServerError("failed to sign", err)
	}

	der := kalkanutil.DERFromPEMOrDER([]byte(certPEM))

	return dto.SbaSignResponse{
		StatusResponse: dto.OK(),
		Certificate:    base64.StdEncoding.EncodeToString(der),
		Signature:      base64.StdEncoding.EncodeToString(signature),
	}, nil
}

// verify реализует /x509/verify: проверка сырой подписи (не CMS) по
// публичному ключу переданного сертификата.
func verify(a *app.App, req dto.SbaVerifyRequest) (dto.VerificationResponse, error) {
	der, err := base64.StdEncoding.DecodeString(kalkanutil.StripWhitespace(req.Certificate))
	if err != nil {
		return dto.VerificationResponse{StatusResponse: dto.OK(), Valid: false, Signers: []*dto.CertificateInfo{nil}}, nil
	}

	certPEM := kalkanutil.PEMFromDER(der)

	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return dto.VerificationResponse{}, httpapi.ClientError("signature is not valid base64", err)
	}

	_, verifyErr := a.Shared.VerifyRaw([]byte(req.Data), signature, certPEM)

	certInfo, err := certservice.Build(a.Shared, a.CRL, certPEM, req.HasOCSP(), req.HasCRL())
	if err != nil {
		return dto.VerificationResponse{}, httpapi.ServerError("failed to build certificate info", err)
	}

	valid := verifyErr == nil && certInfo.Valid

	return dto.VerificationResponse{StatusResponse: dto.OK(), Valid: valid, Signers: []*dto.CertificateInfo{&certInfo}}, nil
}
