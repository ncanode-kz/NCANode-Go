// Package certservice - аналог kz.ncanode.service.CertificateService: сборка
// CertificateInfo (разбор + проверка отозванности) - общая логика для
// x509/pkcs12/cms/xml/wsse/pdf эндпоинтов.
package certservice

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
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
	parsed, parseErr := parseCertPEM(certPEM)
	if parseErr != nil {
		return dto.CertificateInfo{}, fmt.Errorf("parse certificate: %w", parseErr)
	}

	selfSigned := string(parsed.RawIssuer) == string(parsed.RawSubject)

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
		base = minimalInfoFromGoX509(parsed)
	}

	if selfSigned {
		base.Valid = false
	}

	if checkCRL && !selfSigned {
		revoked, checked, paths := checkCRLPaths(cli, crl, certPEM)
		if checked {
			rev := gokalkan.Revocation{Type: gokalkan.RevocationTypeCRL, Revoked: revoked}
			if revoked {
				// Сам факт отзыва уже подтверждён нативной проверкой выше -
				// структурный разбор здесь только чтобы достать точные
				// revocationTime/reason (см. crlentry.go), которых нативная
				// библиотека в текстовом отчёте для CRL не даёт.
				if entry, found := findCRLEntryInPaths(paths, parsed.SerialNumber); found {
					rev.RevokedAt = entry.RevokedAt
					rev.Reason = entry.Reason
				}
				base.Valid = false
			}
			base.Revocations = append(base.Revocations, rev)
		}
	}

	surName, _ := cli.X509CertificateGetInfo(certPEM, ckalkan.CertPropSubjectSurname)

	return toDTO(base, cleanupPrefixed(surName, "=")), nil
}

// checkCRLPaths проверяет сертификат по всем закэшированным CRL (сперва
// delta, потом full - как в Java CrlService: свежие отзывы важнее), и
// возвращает revoked=true при первом же совпадении. checked=false, если ни
// один CRL-файл не удалось использовать (например кэш ещё не наполнен).
// paths - список путей, по которым шла проверка (для последующего
// структурного поиска точной записи, см. findCRLEntryInPaths).
func checkCRLPaths(cli *gokalkan.Client, crl *crlservice.Service, certPEM string) (revoked, checked bool, paths []string) {
	if crl == nil {
		return false, false, nil
	}

	paths = append(append([]string{}, crl.DeltaPaths()...), crl.FullPaths()...)

	for _, path := range paths {
		_, err := cli.ValidateCertCRL(certPEM, path)
		if err == nil {
			checked = true
			continue
		}

		if code, ok := ckalkan.GetErrorCode(err); ok && code == ckalkan.ErrorCodeCertStatusRevoked {
			return true, true, paths
		}
		// прочие ошибки (например сертификат не относится к этому CRL) -
		// игнорируем и пробуем следующий файл.
	}

	return false, checked, paths
}

// findCRLEntryInPaths ищет структурную запись об отзыве (см. crlentry.go) по
// всем закэшированным CRL-файлам - независимо от того, в каком из них её
// нашла нативная проверка (checkCRLPaths это не сообщает).
func findCRLEntryInPaths(paths []string, serial *big.Int) (crlEntry, bool) {
	for _, path := range paths {
		if entry, found := findCRLEntry(path, serial); found {
			return entry, true
		}
	}

	return crlEntry{}, false
}

// parseCertPEM разбирает PEM (или голый DER, на всякий случай - как и раньше)
// стандартной библиотекой - используется и для определения self-signed, и
// как запасной путь при ошибке нативного разбора (см. Build), и для серийного
// номера при структурном поиске записи в CRL (см. findCRLEntryInPaths).
func parseCertPEM(certPEM string) (*x509.Certificate, error) {
	der := []byte(certPEM)
	if block, _ := pem.Decode([]byte(certPEM)); block != nil {
		der = block.Bytes
	}

	return x509.ParseCertificate(der)
}

// minimalInfoFromGoX509 - запасной путь для сертификатов, форма которых не
// укладывается в предположения gokalkan.GetCertificateInfo (см. Build) -
// достаёт то немногое, что нужно для ответа, без обращения к KalkanCrypt.
func minimalInfoFromGoX509(cert *x509.Certificate) *gokalkan.CertificateInfo {
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
			Revoked:        r.Revoked,
			By:             string(r.Type),
			RevocationTime: revocationTimeFor(r),
			Reason:         reasonFor(r),
		})
	}

	return out
}

// revocationTimeFor форматирует точное время отзыва (см. gokalkan.Revocation.RevokedAt
// для OCSP, findCRLEntryInPaths для CRL) - nil, если сертификат не отозван
// или время не удалось извлечь.
func revocationTimeFor(r gokalkan.Revocation) *string {
	if !r.Revoked || r.RevokedAt.IsZero() {
		return nil
	}

	formatted := r.RevokedAt.UTC().Format(DateLayout)

	return &formatted
}

// reasonFor - причина отзыва в терминах Java (см. OcspStatus/CrlStatus в
// NCANode):
//
//   - OCSP: Java (OcspService.processOcspResponse) безусловно пишет "OK" в
//     message - и для отозванного, и для активного статуса; сам
//     revocationReason (CRLReason) для OCSP в JSON не попадает вообще.
//   - CRL, не отозван: Java (CrlService.verify) в этой ветке вообще не
//     вызывает .reason(...) - в JSON явный null (см. dto.Revocation).
//   - CRL, отозван: r.Reason - уже посчитанное имя причины в стиле
//     java.security.cert.CRLReason (см. crlReasonNames), "" если расширение
//     reasonCode в записи CRL отсутствует - тот же случай, что у Java даёт
//     Optional.ofNullable(...).orElse("").
func reasonFor(r gokalkan.Revocation) *string {
	switch {
	case r.Type == gokalkan.RevocationTypeOCSP:
		reason := "OK"
		return &reason
	case r.Type == gokalkan.RevocationTypeCRL && !r.Revoked:
		return nil
	default:
		reason := r.Reason
		return &reason
	}
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
// показывает Java (java.security.cert.X509Certificate.getSigAlgName(), см.
// CertificateWrapper.java). Это имя резолвит не сама Java, а JCE-провайдер
// KalkanCrypt (kz.gov.pki.kalkan.jce.provider.KalkanProvider) через записи
// "Alg.Alias.Signature.<OID>" в своей таблице алгоритмов.
//
// Записи ниже сверены не эмпирически с живым Java-сервисом, а декомпиляцией
// байткода того же provider-jar, который тянет эталонный NCANode
// (knca_provider_jce_kalkan-0.7.5.jar, см. addSignatureAlgorithm/
// KalkanProvider.<init> и *ObjectIdentifiers.<clinit> в KalkanProvider.class,
// PKCSObjectIdentifiers.class, OIWObjectIdentifiers.class,
// CryptoProObjectIdentifiers.class, KNCAObjectIdentifiers.class) - то есть
// это тот же источник истины, что использует сам Java в рантайме, просто
// прочитанный статически. Единственная запись, подтверждённая вживую через
// сверку с работающим Java NCANode - ECGOST3410-2015-512.
//
//nolint:gochecknoglobals
var signAlgByOID = map[string]string{
	// RSA (PKCS#1) - kz/gov/pki/kalkan/asn1/pkcs/PKCSObjectIdentifiers.class.
	"1.2.840.113549.1.1.2":  "MD2WithRSAEncryption",
	"1.2.840.113549.1.1.3":  "MD4WithRSAEncryption",
	"1.2.840.113549.1.1.4":  "MD5WithRSAEncryption",
	"1.2.840.113549.1.1.5":  "SHA1WithRSAEncryption",
	"1.2.840.113549.1.1.11": "SHA256WithRSAEncryption",
	"1.2.840.113549.1.1.12": "SHA384WithRSAEncryption",
	"1.2.840.113549.1.1.13": "SHA512WithRSAEncryption",
	"1.2.840.113549.1.1.14": "SHA224WithRSAEncryption",
	// SHA1WithRSA (OIW-алиас того же алгоритма) -
	// kz/gov/pki/kalkan/asn1/oiw/OIWObjectIdentifiers.class.
	"1.3.14.3.2.29": "SHA1WithRSAEncryption",
	// ГОСТ Р 34.10-94/2001 (CryptoPro) -
	// kz/gov/pki/kalkan/asn1/cryptopro/CryptoProObjectIdentifiers.class.
	"1.2.643.2.2.4": "GOST3410",
	"1.2.643.2.2.3": "ECGOST3410",
	// ГОСТ 34.310-2004 (KZ, kalkan-специфичный OID CryptoPro-семейства) -
	// kz/gov/pki/kalkan/asn1/cryptopro/CryptoProObjectIdentifiers.class.
	"1.3.6.1.4.1.6801.1.2.2": "ECGOST34310",
	// ГОСТ 34.310-2004 (KZ, KNCA OID) -
	// kz/gov/pki/kalkan/asn1/knca/KNCAObjectIdentifiers.class.
	"1.2.398.3.10.1.1.1.2": "ECGOST34310",
	// ГОСТ Р 34.10-2015 (KZ) -
	// kz/gov/pki/kalkan/asn1/knca/KNCAObjectIdentifiers.class.
	"1.2.398.3.10.1.1.2.3.1": "ECGOST3410-2015-256",
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
