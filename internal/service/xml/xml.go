// Package xml - HTTP-хендлеры /xml/sign, /xml/verify (аналог
// kz.ncanode.service.XmlService).
package xml

import (
	"fmt"
	"net/http"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/certservice"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
	"github.com/ncanode-kz/gokalkan"
)

func RegisterRoutes(s *httpapi.Server, a *app.App) {
	httpapi.Handle(s, "POST /xml/sign", func(r *http.Request, req dto.XmlSignRequest) (dto.XmlSignResponse, error) {
		return sign(a, req)
	})
	httpapi.Handle(s, "POST /xml/verify", func(r *http.Request, req dto.XmlVerifyRequest) (dto.VerificationResponse, error) {
		return verify(a, req.XML, req.HasOCSP(), req.HasCRL())
	})
}

// sign реализует /xml/sign: clearSignatures/trimXml применяются один раз (как
// в Java XmlService.sign - до цикла по подписантам), затем каждый signer
// добавляет свою ds:Signature поверх результата предыдущего.
func sign(a *app.App, req dto.XmlSignRequest) (dto.XmlSignResponse, error) {
	if len(req.Signers) == 0 {
		return dto.XmlSignResponse{}, httpapi.ClientError("signers must not be empty", nil)
	}

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	xmlData := req.XML

	for i, signer := range req.Signers {
		if _, err := kalkanutil.LoadSigner(a.Shared, signer.Key, signer.Password); err != nil {
			return dto.XmlSignResponse{}, httpapi.ServerError(fmt.Sprintf("failed to load signer #%d", i), err)
		}

		opts := gokalkan.XMLSignOptions{ReferenceURI: signer.ReferenceURI}
		if i == 0 {
			opts.ClearSignatures = req.ClearSignatures
			opts.TrimXML = req.TrimXML
		}

		signed, err := a.Shared.SignXMLWithOptions(xmlData, opts)
		if err != nil {
			return dto.XmlSignResponse{}, httpapi.ServerError(fmt.Sprintf("failed to sign with signer #%d", i), err)
		}

		xmlData = signed
	}

	return dto.XmlSignResponse{StatusResponse: dto.OK(), XML: xmlData}, nil
}

// verify реализует /xml/verify. Как и Java, отдаёт подписантов в порядке
// от последней подписи к первой (см. XmlService.verify - обрабатывает и
// удаляет ds:Signature с конца документа на каждой итерации).
func verify(a *app.App, xmlData string, checkOCSP, checkCRL bool) (dto.VerificationResponse, error) {
	_, verifyErr := a.Shared.VerifyXML(xmlData)

	var signers []*dto.CertificateInfo
	valid := verifyErr == nil

	for i := 1; ; i++ {
		certDER, err := a.Shared.GetCertFromXML(xmlData, i)
		if err != nil || len(certDER) == 0 {
			break
		}

		certInfo, err := certservice.Build(a.Shared, a.CRL, kalkanutil.PEMFromBase64Body(certDER), checkOCSP, checkCRL)
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

	if len(signers) == 0 {
		valid = false
	} else {
		reverseSigners(signers)
	}

	return dto.VerificationResponse{StatusResponse: dto.OK(), Valid: valid, Signers: signers}, nil
}

func reverseSigners(s []*dto.CertificateInfo) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
