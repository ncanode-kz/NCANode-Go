package certservice

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"time"
)

// crlEntry - структурный результат поиска сертификата в CRL: точное время
// отзыва и причина (см. findCRLEntry).
type crlEntry struct {
	RevokedAt time.Time
	// Reason - имя причины отзыва в стиле java.security.cert.CRLReason
	// (см. crlReasonNames), "" если расширение reasonCode (2.5.29.21) в
	// записи CRL отсутствует (тот же случай, что у Java даёт
	// Optional.ofNullable(...).orElse("") в CrlService.verify).
	Reason string
}

// certificateList/tbsCertificateList - минимальный ASN.1 (RFC 5280 §5.1)
// разбор CRL напрямую, в обход crypto/x509.ParseRevocationList: у стандартной
// библиотеки есть дополнительная проверка "inner and outer signature
// algorithm identifiers match", которая на живых ГОСТ-CRL pki.gov.kz не
// проходит (сверено эмпирически на internal/testdata/certs/*.crl) - хотя сама
// структура CRL при этом парсится корректно. Подпись самого CRL не
// проверяется - как и Java (X509CRL здесь используется только чтобы найти
// запись по serialNumber, доверие обеспечивается тем, что файл уже прошёл
// нативную проверку в checkCRLPaths).
type certificateList struct {
	TBSCertList        tbsCertificateList
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificateList struct {
	Raw                 asn1.RawContent
	Version             int `asn1:"optional,default:0"`
	Signature           pkix.AlgorithmIdentifier
	Issuer              asn1.RawValue
	ThisUpdate          time.Time
	NextUpdate          time.Time                 `asn1:"optional"`
	RevokedCertificates []pkix.RevokedCertificate `asn1:"optional"`
	Extensions          []pkix.Extension          `asn1:"tag:0,optional,explicit"`
}

// oidCRLReasonCode - OID расширения записи CRL reasonCode (RFC 5280 §5.3.1).
//
//nolint:gochecknoglobals
var oidCRLReasonCode = asn1.ObjectIdentifier{2, 5, 29, 21}

// crlReasonNames - имена причин отзыва в порядке кодов RFC 5280 §5.3.1, в
// точности как их печатает java.security.cert.CRLReason.toString() (обычный
// Enum.toString - имя константы как есть). Индекс 7 ("unused") в JDK
// зарезервирован под имя "UNUSED".
//
//nolint:gochecknoglobals
var crlReasonNames = []string{
	"UNSPECIFIED",
	"KEY_COMPROMISE",
	"CA_COMPROMISE",
	"AFFILIATION_CHANGED",
	"SUPERSEDED",
	"CESSATION_OF_OPERATION",
	"CERTIFICATE_HOLD",
	"UNUSED",
	"REMOVE_FROM_CRL",
	"PRIVILEGE_WITHDRAWN",
	"AA_COMPROMISE",
}

// findCRLEntry читает CRL-файл по path и ищет в нём запись с заданным
// serialNumber. found=false, если файл не прочитался/не распарсился или
// сертификат в нём не найден - вызывающий код (checkCRLPaths) в этом случае
// просто не заполняет RevokedAt/Reason, не считая это ошибкой (сама
// отозванность уже подтверждена нативной проверкой).
func findCRLEntry(path string, serial *big.Int) (entry crlEntry, found bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return crlEntry{}, false
	}

	var cl certificateList
	if _, err := asn1.Unmarshal(raw, &cl); err != nil {
		return crlEntry{}, false
	}

	for _, rc := range cl.TBSCertList.RevokedCertificates {
		if rc.SerialNumber == nil || rc.SerialNumber.Cmp(serial) != 0 {
			continue
		}

		return crlEntry{RevokedAt: rc.RevocationTime, Reason: crlReasonFromExtensions(rc.Extensions)}, true
	}

	return crlEntry{}, false
}

func crlReasonFromExtensions(extensions []pkix.Extension) string {
	for _, ext := range extensions {
		if !ext.Id.Equal(oidCRLReasonCode) {
			continue
		}

		var code asn1.Enumerated
		if _, err := asn1.Unmarshal(ext.Value, &code); err != nil {
			continue
		}

		if code >= 0 && int(code) < len(crlReasonNames) {
			return crlReasonNames[code]
		}
	}

	return ""
}
