// Package certservice - аналог kz.ncanode.service.CertificateService: сборка
// CertificateInfo (разбор + проверка отозванности) - общая логика для
// x509/pkcs12/cms/xml/wsse/pdf эндпоинтов.
package certservice

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/ncanode-kz/NCANode-Go/internal/crlservice"
	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/gokalkan"
	"github.com/ncanode-kz/gokalkan/ckalkan"
)

// DateLayout - формат даты, который Jackson/Java по умолчанию использует для
// java.util.Date: миллисекунды + смещение с двоеточием, в UTC ("+00:00" -
// не "Z"; сверено с реальным ответом живого NCANode).
const DateLayout = "2006-01-02T15:04:05.000-07:00"

// Build собирает dto.CertificateInfo из PEM-сертификата. checkOCSP/checkCRL -
// запрошенные клиентом проверки отозванности (см. dto.VerifyRequest).
//
// Самоподписанные сертификаты никогда не проходят как valid (нет издателя,
// которому можно доверять - как и в Java), и для них НЕ вызывается нативная
// проверка цепочки/отозванности: экспериментально установлено, что
// X509ValidateCertificate роняет процесс сегфолтом на self-signed
// сертификате (см. gokalkan Phase 1) - в отличие от Java, у нас нет
// возможности перехватить сегфолт, поэтому проверка self-signed идёт первым
// делом на чистом Go (crypto/x509), до какого-либо обращения к KalkanCrypt.
func Build(cli *gokalkan.Client, crl *crlservice.Service, certPEM string, checkOCSP, checkCRL bool) (dto.CertificateInfo, error) {
	selfSigned, parseErr := isSelfSigned(certPEM)
	if parseErr != nil {
		return dto.CertificateInfo{}, fmt.Errorf("parse certificate: %w", parseErr)
	}

	base, err := cli.GetCertificateInfo(certPEM, checkOCSP && !selfSigned, "")
	if err != nil {
		if !selfSigned {
			return dto.CertificateInfo{}, err
		}

		// GetCertificateInfo опирается на набор нативных X509CertificateGetInfo
		// вызовов, рассчитанных на форму персонального/организационного
		// сертификата (GivenName, ExtKeyUsage и т.д.) - у корневых/self-signed
		// сертификатов части этих полей может не быть, и вызов падает с
		// ошибкой. Раз self-signed в любом случае никогда не valid, в этом
		// случае просто собираем минимальную информацию средствами
		// стандартного crypto/x509, не полагаясь на KalkanCrypt.
		base = minimalInfoFromGoX509(certPEM)
	}

	if selfSigned {
		base.Valid = false
	}

	if checkCRL && !selfSigned {
		revoked, checked := checkCRLPaths(cli, crl, certPEM)
		if checked {
			base.Revocations = append(base.Revocations, gokalkan.Revocation{
				Type:    gokalkan.RevocationTypeCRL,
				Revoked: revoked,
			})
			if revoked {
				base.Valid = false
			}
		}
	}

	surName, _ := cli.X509CertificateGetInfo(certPEM, ckalkan.CertPropSubjectSurname)

	return toDTO(base, cleanupPrefixed(surName, "=")), nil
}

// checkCRLPaths проверяет сертификат по всем закэшированным CRL (сперва
// delta, потом full - как в Java CrlService: свежие отзывы важнее), и
// возвращает revoked=true при первом же совпадении. checked=false, если ни
// один CRL-файл не удалось использовать (например кэш ещё не наполнен).
func checkCRLPaths(cli *gokalkan.Client, crl *crlservice.Service, certPEM string) (revoked, checked bool) {
	if crl == nil {
		return false, false
	}

	paths := append(append([]string{}, crl.DeltaPaths()...), crl.FullPaths()...)

	for _, path := range paths {
		_, err := cli.ValidateCertCRL(certPEM, path)
		if err == nil {
			checked = true
			continue
		}

		if code, ok := ckalkan.GetErrorCode(err); ok && code == ckalkan.ErrorCodeCertStatusRevoked {
			return true, true
		}
		// прочие ошибки (например сертификат не относится к этому CRL) -
		// игнорируем и пробуем следующий файл.
	}

	return false, checked
}

func isSelfSigned(certPEM string) (bool, error) {
	der := []byte(certPEM)
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return false, err
	}

	return string(cert.RawIssuer) == string(cert.RawSubject), nil
}

// minimalInfoFromGoX509 - запасной путь для сертификатов, форма которых не
// укладывается в предположения gokalkan.GetCertificateInfo (см. Build) -
// достаёт то немногое, что нужно для ответа, без обращения к KalkanCrypt.
func minimalInfoFromGoX509(certPEM string) *gokalkan.CertificateInfo {
	der := []byte(certPEM)
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return &gokalkan.CertificateInfo{}
	}

	return &gokalkan.CertificateInfo{
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		SerialNumber: strings.ToLower(cert.SerialNumber.Text(16)),
		Subject: gokalkan.CertSubject{
			CommonName: cert.Subject.CommonName,
			Country:    strings.Join(cert.Subject.Country, ","),
		},
		Issuer: gokalkan.CertIssuer{
			CommonName: cert.Issuer.CommonName,
			Country:    strings.Join(cert.Issuer.Country, ","),
		},
	}
}

func toDTO(info *gokalkan.CertificateInfo, surName string) dto.CertificateInfo {
	out := dto.CertificateInfo{
		Valid:        info.Valid,
		NotBefore:    info.NotBefore.UTC().Format(DateLayout),
		NotAfter:     info.NotAfter.UTC().Format(DateLayout),
		KeyUsage:     string(info.KeyUsage),
		SerialNumber: info.SerialNumber,
		SignAlg:      shortSignAlg(info.SignAlg),
		KeyUser:      reorderKeyUser(info.KeyUser),
		PublicKey:    info.PublicKey,
		Signature:    info.Signature,
		Subject: dto.CertSubject{
			CommonName: info.Subject.CommonName,
			SurName:    surName,
			Country:    info.Subject.Country,
			IIN:        info.Subject.IIN,
			DN:         info.Subject.DN,
		},
		Issuer: dto.CertIssuer{
			CommonName: info.Issuer.CommonName,
			Country:    info.Issuer.Country,
			DN:         info.Issuer.DN,
		},
	}

	if info.Organization != nil {
		out.Subject.BIN = info.Organization.BIN
		out.Subject.Organization = info.Organization.Name
	}

	out.Revocations = make([]dto.Revocation, 0, len(info.Revocations))
	for _, r := range info.Revocations {
		out.Revocations = append(out.Revocations, dto.Revocation{
			Revoked: r.Revoked,
			By:      string(r.Type),
			// RevocationTime: gokalkan сейчас не извлекает точное время
			// отзыва из нативного ответа OCSP/CRL, только сам факт - в
			// отличие от Java, которая парсит его из ответа. Известное
			// упрощение, см. README.
			RevocationTime: nil,
			Reason:         reasonFor(r),
		})
	}

	return out
}

// reasonFor - для OCSP-проверки непросроченного сертификата Java пишет "OK"
// даже когда revoked=false; для остальных случаев причина - текст ошибки
// нативной библиотеки (если есть).
func reasonFor(r gokalkan.Revocation) string {
	if !r.Revoked {
		return "OK"
	}
	if r.Reason != "" {
		return r.Reason
	}
	return "REVOKED"
}

// reorderKeyUser ставит специфичную роль перед общим типом (ORGANIZATION),
// как это делает Java (например ["CEO","ORGANIZATION"], а не наоборот).
func reorderKeyUser(keyUser []string) []string {
	if len(keyUser) == 2 && keyUser[0] == "ORGANIZATION" {
		return []string{keyUser[1], keyUser[0]}
	}
	return keyUser
}

// signAlgByOID - соответствие OID алгоритма подписи короткому имени, как его
// показывает Java (KalkanUtil). Подтверждено сверкой с живым NCANode только
// для ECGOST3410-2015-512 (единственный алгоритм, встретившийся в тестовых
// сертификатах на момент написания) - остальные записи отсутствуют, при
// неизвестном OID возвращается сырой ответ нативной библиотеки как есть.
//
//nolint:gochecknoglobals
var signAlgByOID = map[string]string{
	"1.2.398.3.10.1.1.2.3.2": "ECGOST3410-2015-512",
}

func shortSignAlg(raw string) string {
	start := strings.LastIndexByte(raw, '(')
	end := strings.LastIndexByte(raw, ')')
	if start == -1 || end == -1 || end <= start {
		return raw
	}

	oid := raw[start+1 : end]
	if short, ok := signAlgByOID[oid]; ok {
		return short
	}

	return oid
}

func cleanupPrefixed(value, sep string) string {
	if parts := strings.SplitN(value, sep, 2); len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return value
}
