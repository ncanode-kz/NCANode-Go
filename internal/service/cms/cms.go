// Package cms - HTTP-хендлеры /cms/sign, /cms/sign/add, /cms/verify,
// /cms/extract (аналог kz.ncanode.service.CmsService).
package cms

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/ncanode-kz/NCANode-Go/internal/app"
	"github.com/ncanode-kz/NCANode-Go/internal/certservice"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/httpapi"
	"github.com/ncanode-kz/NCANode-Go/internal/kalkanutil"
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
		if _, err := kalkanutil.LoadSigner(cli, signer.Key, signer.Password); err != nil {
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

	var info string
	var cryptoErr error

	if req.Data != "" {
		data, decodeErr := base64.StdEncoding.DecodeString(req.Data)
		if decodeErr != nil {
			return dto.CmsVerificationResponse{}, httpapi.ClientError("data is not valid base64", decodeErr)
		}
		info, cryptoErr = cli.VerifyDetached(cms, data)
	} else {
		info, cryptoErr = cli.Verify(cms)
	}

	signingTimes := extractSigningTimes(info)

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
		if t, ok := signingTimes[i]; ok {
			signerInfo.TSP = &dto.TspInfo{GenTime: &t}
		}

		signers = append(signers, signerInfo)
	}

	if len(signers) == 0 {
		valid = false
	}

	return dto.CmsVerificationResponse{StatusResponse: dto.OK(), Valid: valid, Signers: signers}, nil
}

// extractSigningTimes парсит время подписи из человекочитаемого отчёта
// нативной библиотеки (Client.Verify/VerifyDetached), по одному "Signature N
// k" блоку - ключ карты 1-based, как нумерует сама нативная библиотека.
//
// gokalkan сейчас не возвращает эту информацию структурно (только текстовый
// отчёт), поэтому остальные поля TspInfo (serialNumber/policy/tsa/hash)
// заполнить нечем - известное упрощение, см. README.
func extractSigningTimes(info string) map[int]string {
	result := make(map[int]string)

	sections := signatureHeaderRe.Split(info, -1)
	headers := signatureHeaderRe.FindAllStringSubmatch(info, -1)

	for i, h := range headers {
		if i+1 >= len(sections) {
			break
		}

		m := signingTimeRe.FindStringSubmatch(sections[i+1])
		if m == nil {
			continue
		}

		n, err := strconv.Atoi(h[1])
		if err != nil {
			continue
		}

		t, err := time.Parse("02.01.2006 15:04:05 -07:00", m[1])
		if err != nil {
			continue
		}

		formatted := t.UTC().Format(certservice.DateLayout)
		result[n] = formatted
	}

	return result
}

//nolint:gochecknoglobals
var (
	signatureHeaderRe = regexp.MustCompile(`Signature N (\d+)`)
	signingTimeRe     = regexp.MustCompile(`Signing time (\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2} [+-]\d{2}:\d{2})`)
)
