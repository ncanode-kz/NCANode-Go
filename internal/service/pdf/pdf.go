// Package pdf - HTTP-хендлеры /pdf/sign, /pdf/verify (аналог
// kz.ncanode.service.PdfService).
package pdf

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/digitorus/pkcs7"
	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/certservice"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
	"github.com/ncanode-kz/gokalkan"
)

func RegisterRoutes(s *httpapi.Server, a *app.App) {
	httpapi.Handle(s, "POST /pdf/sign", func(r *http.Request, req dto.PdfSignRequest) (dto.PdfSignResponse, error) {
		return sign(a, req)
	})
	httpapi.Handle(s, "POST /pdf/verify", func(r *http.Request, req dto.PdfVerifyRequest) (dto.PdfVerificationResponse, error) {
		return verify(a, req)
	})
}

// sign реализует /pdf/sign: каждый подписант добавляет свою CAdES-detached
// подпись поверх результата предыдущего (incremental update), как и
// document.addSignature(...) в цикле у Java PdfService.sign.
func sign(a *app.App, req dto.PdfSignRequest) (dto.PdfSignResponse, error) {
	if len(req.Signers) == 0 {
		return dto.PdfSignResponse{}, httpapi.ClientError("signers must not be empty", nil)
	}

	pdfData, err := base64.StdEncoding.DecodeString(req.PDF)
	if err != nil {
		return dto.PdfSignResponse{}, httpapi.ClientError("pdf is not valid base64", err)
	}

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	for i, signer := range req.Signers {
		if _, err := kalkanutil.LoadSigner(a.Shared, signer.Signer.Key, signer.Signer.Password, signer.Signer.KeyAlias); err != nil {
			return dto.PdfSignResponse{}, httpapi.ServerError(fmt.Sprintf("failed to load signer #%d", i), err)
		}

		pdfData, err = a.Shared.SignPDF(pdfData, gokalkan.PDFSignOptions{
			Location:    signer.Location,
			Reason:      signer.Reason,
			ContactInfo: signer.ContactInfo,
			WithTSP:     req.WithTSP,
		})
		if err != nil {
			return dto.PdfSignResponse{}, httpapi.ServerError(fmt.Sprintf("failed to sign with signer #%d", i), err)
		}
	}

	return dto.PdfSignResponse{StatusResponse: dto.OK(), PDF: base64.StdEncoding.EncodeToString(pdfData)}, nil
}

func verify(a *app.App, req dto.PdfVerifyRequest) (dto.PdfVerificationResponse, error) {
	pdfData, err := base64.StdEncoding.DecodeString(req.PDF)
	if err != nil {
		return dto.PdfVerificationResponse{}, httpapi.ClientError("pdf is not valid base64", err)
	}

	_, signers, err := a.Shared.VerifyPDF(pdfData)
	if err != nil {
		if errors.Is(err, gokalkan.ErrNoPDFSignatures) {
			return dto.PdfVerificationResponse{}, httpapi.NotFoundError("PDF document contains no digital signatures", err)
		}
		return dto.PdfVerificationResponse{}, httpapi.ServerError("failed to verify pdf", err)
	}

	// allValid из VerifyPDF отражает только криптографическую проверку CMS;
	// пересчитываем с учётом валидности сертификата (цепочка/отозванность),
	// как это делает Java (cmsOk && cert.isValid(...)).
	out := make([]dto.PdfSignerInfo, 0, len(signers))
	allValid := true

	for _, s := range signers {
		info := dto.PdfSignerInfo{
			Valid:              s.Valid,
			Reason:             s.Reason,
			Location:           s.Location,
			ContactInfo:        s.ContactInfo,
			SignatureAlgorithm: s.SubFilter,
			DigestAlgorithm:    digestAlgorithmOID(s.CMS),
		}

		if !s.SignDate.IsZero() {
			formatted := s.SignDate.UTC().Format(certservice.DateLayout)
			info.SignDate = &formatted
		}

		if len(s.CMS) > 0 {
			// Как и в /cms/verify, GetCertFromCMS нумерует подписантов с 1
			// (см. service/cms) - detached CMS каждой PDF-подписи содержит
			// ровно одного подписанта.
			if certPEM, err := a.Shared.GetCertFromCMS(s.CMS, 1); err == nil {
				certInfo, err := certservice.Build(a.Shared, a.CRL, certPEM, req.HasOCSP(), req.HasCRL())
				if err == nil {
					info.Certificate = &certInfo
					if !certInfo.Valid {
						info.Valid = false
					}
				} else {
					info.Valid = false
				}
			} else {
				info.Valid = false
			}
		} else {
			info.Valid = false
		}

		if !info.Valid {
			allValid = false
		}

		out = append(out, info)
	}

	if len(out) == 0 {
		allValid = false
	}

	return dto.PdfVerificationResponse{StatusResponse: dto.OK(), Valid: allValid, Signers: out}, nil
}

// digestAlgorithmOID достаёт OID алгоритма хэширования CMS (отдельно от
// signatureAlgorithm/SubFilter) структурным ASN.1-разбором detached-подписи -
// аналог si.getDigestAlgOID() в Java PdfService, где si - CMS SignerInfo,
// полученный тем же способом (разбор самого CMS, без обращения к
// KalkanCrypt). "unknown" - тот же фолбэк, что и в Java, на случай если CMS
// не распарсился или не содержит подписантов.
func digestAlgorithmOID(cms []byte) string {
	p7, err := pkcs7.Parse(cms)
	if err != nil || len(p7.Signers) == 0 {
		return "unknown"
	}

	return p7.Signers[0].DigestAlgorithm.Algorithm.String()
}
