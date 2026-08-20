// Package cms - HTTP-хендлеры /cms/sign, /cms/sign/add, /cms/verify,
// /cms/extract (аналог kz.ncanode.service.CmsService).
package cms

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/digitorus/pkcs7"
	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/certservice"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
	"github.com/ncanode-kz/NCANode-Go/internal/tsp"
	"github.com/ncanode-kz/gokalkan"
)

func RegisterRoutes(s *httpapi.Server, a *app.App) {
	httpapi.Handle(s, "POST /cms/sign", func(r *http.Request, req dto.CmsCreateRequest) (dto.CmsResponse, error) {
		return sign(a, req, false)
	})
	httpapi.Handle(s, "POST /cms/sign/add", func(r *http.Request, req dto.CmsCreateRequest) (dto.CmsResponse, error) {
		return sign(a, req, true)
	})
	httpapi.Handle(s, "POST /cms/verify", func(r *http.Request, req dto.CmsVerifyRequest) (dto.CmsVerificationResponse, error) {
		return verify(a, req)
	})
	httpapi.Handle(s, "POST /cms/extract", func(r *http.Request, req dto.CmsVerifyRequest) (dto.CmsDataResponse, error) {
		return extract(a, req)
	})
}

// sign реализует /cms/sign (add=false) и /cms/sign/add (add=true) - оба
// используют один и тот же запрос (kz.ncanode.dto.request.CmsCreateRequest)
// и один и тот же паттерн: подписать N раз подряд, каждый следующий сигнер
// добавляется в уже готовый CMS предыдущего шага (см. gokalkan.AddSigner -
// экспериментально подтверждено, что это даёт тот же результат, что
// однопроходная многоподписантная генерация в Java, см. gokalkan Phase 1).
func sign(a *app.App, req dto.CmsCreateRequest, add bool) (dto.CmsResponse, error) {
	if len(req.Signers) == 0 {
		return dto.CmsResponse{}, httpapi.ClientError("signers must not be empty", nil)
	}

	a.SigningMu.Lock()
	defer a.SigningMu.Unlock()

	cli := a.Shared

	var cms []byte
	var err error

	content, err := resolveSignContent(cli, req, add)
	if err != nil {
		return dto.CmsResponse{}, err
	}

	if add {
		existing, decodeErr := base64.StdEncoding.DecodeString(req.CMS)
		if decodeErr != nil {
			return dto.CmsResponse{}, httpapi.ClientError("cms is not valid base64", decodeErr)
		}
		cms = existing
	}

	for i, signer := range req.Signers {
		if _, err := kalkanutil.LoadSigner(cli, signer.Key, signer.Password, signer.KeyAlias); err != nil {
			return dto.CmsResponse{}, httpapi.ServerError(fmt.Sprintf("failed to load signer #%d", i), err)
		}

		if !add && i == 0 {
			cms, err = cli.Sign(content, req.Detached, req.WithTSP)
		} else {
			cms, err = cli.AddSigner(cms, content, req.Detached, req.WithTSP)
		}
		if err != nil {
			return dto.CmsResponse{}, httpapi.ServerError(fmt.Sprintf("failed to sign with signer #%d", i), err)
		}
	}

	return dto.CmsResponse{StatusResponse: dto.OK(), CMS: base64.StdEncoding.EncodeToString(cms)}, nil
}

func resolveSignContent(cli *gokalkan.Client, req dto.CmsCreateRequest, add bool) ([]byte, error) {
	if !add {
		if req.Data == "" {
			return nil, httpapi.ClientError("data must not be empty", nil)
		}
		content, err := base64.StdEncoding.DecodeString(req.Data)
		if err != nil {
			return nil, httpapi.ClientError("data is not valid base64", err)
		}
		return content, nil
	}

	if req.CMS == "" {
		return nil, httpapi.ClientError("CMS argument not specified", nil)
	}

	existing, err := base64.StdEncoding.DecodeString(req.CMS)
	if err != nil {
		return nil, httpapi.ClientError("cms is not valid base64", err)
	}

	// Как и в Java: сперва пробуем достать вложенные данные из самого CMS
	// (attached), и только если их нет - требуем поле data (detached).
	if embedded, err := cli.ExtractCMS(existing); err == nil {
		return embedded, nil
	}

	if req.Data == "" {
		return nil, httpapi.ClientError("Data must be specified for detached CMS", nil)
	}

	content, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return nil, httpapi.ClientError("data is not valid base64", err)
	}

	return content, nil
}

func extract(a *app.App, req dto.CmsVerifyRequest) (dto.CmsDataResponse, error) {
	if req.CMS == "" {
		return dto.CmsDataResponse{}, httpapi.ClientError("cms is required", nil)
	}

	cms, err := base64.StdEncoding.DecodeString(req.CMS)
	if err != nil {
		return dto.CmsDataResponse{}, httpapi.ClientError("cms is not valid base64", err)
	}

	data, err := a.Shared.ExtractCMS(cms)
	if err != nil {
		return dto.CmsDataResponse{}, httpapi.ClientError("CMS doesn't have signed content", err)
	}

	return dto.CmsDataResponse{StatusResponse: dto.OK(), Data: base64.StdEncoding.EncodeToString(data)}, nil
}

func verify(a *app.App, req dto.CmsVerifyRequest) (dto.CmsVerificationResponse, error) {
	if req.CMS == "" {
		return dto.CmsVerificationResponse{}, httpapi.ClientError("cms is required", nil)
	}

	cms, err := base64.StdEncoding.DecodeString(req.CMS)
	if err != nil {
		return dto.CmsVerificationResponse{}, httpapi.ClientError("cms is not valid base64", err)
	}

	cli := a.Shared

	var cryptoErr error

	if req.Data != "" {
		data, decodeErr := base64.StdEncoding.DecodeString(req.Data)
		if decodeErr != nil {
			return dto.CmsVerificationResponse{}, httpapi.ClientError("data is not valid base64", decodeErr)
		}
		_, cryptoErr = cli.VerifyDetached(cms, data)
	} else {
		_, cryptoErr = cli.Verify(cms)
	}

	tspInfos := extractTspInfos(cms)

	var signers []dto.CmsSignerInfo
	valid := cryptoErr == nil

	// GetCertFromCMS нумерует подписантов с 1 (как и "Signature N 1" в
	// текстовом отчёте Verify/VerifyDetached) - signID=0 не ошибка, а
	// бессмысленный короткий ответ, эмпирически обнаружено.
	for i := 1; ; i++ {
		certPEM, err := cli.GetCertFromCMS(cms, i)
		if err != nil {
			break
		}

		certInfo, err := certservice.Build(cli, a.CRL, certPEM, req.HasOCSP(), req.HasCRL())
		if err != nil {
			valid = false
			continue
		}

		if !certInfo.Valid {
			valid = false
		}

		signerInfo := dto.CmsSignerInfo{Certificates: []dto.CertificateInfo{certInfo}}
		if tsp, ok := tspInfos[i]; ok {
			signerInfo.TSP = &tsp
		}

		signers = append(signers, signerInfo)
	}

	if len(signers) == 0 {
		valid = false
	}

	return dto.CmsVerificationResponse{StatusResponse: dto.OK(), Valid: valid, Signers: signers}, nil
}

// extractTspInfos структурно разбирает CMS (без обращения к KalkanCrypt,
// см. internal/tsp) и собирает TspInfo для каждого подписанта, у которого
// есть unsigned-атрибут id-aa-signatureTimeStampToken - ключ карты 1-based,
// как нумерует GetCertFromCMS/нативная библиотека (см. цикл в verify).
// Порядок p7.Signers, возвращаемый digitorus/pkcs7, эмпирически считается
// совпадающим с этой нумерацией - как и для XML/WSSE (см. README), это
// предположение не документировано производителем нативной библиотеки.
//
// Отсутствие TSP-токена или ошибка разбора конкретного подписанта - не
// фатальны (как и в Java CmsService, где это же оборачивается в try/catch с
// log.warn): просто не добавляем TspInfo для этого подписанта.
func extractTspInfos(cms []byte) map[int]dto.TspInfo {
	result := make(map[int]dto.TspInfo)

	p7, err := pkcs7.Parse(cms)
	if err != nil {
		return result
	}

	for i, signer := range p7.Signers {
		for _, attr := range signer.UnauthenticatedAttributes {
			if attr.Type.String() != tsp.AttributeOID {
				continue
			}

			info, err := tsp.Extract(attr.Value.Bytes)
			if err != nil {
				continue
			}

			genTime := info.GenTime.UTC().Format(certservice.DateLayout)
			result[i+1] = dto.TspInfo{
				SerialNumber:     info.SerialNumber,
				GenTime:          &genTime,
				Policy:           info.Policy,
				TSPHashAlgorithm: info.TSPHashAlgorithm,
				Hash:             info.Hash,
			}

			break
		}
	}

	return result
}
