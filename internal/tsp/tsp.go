// Package tsp разбирает RFC3161 TimeStampToken, вложенный в CMS как
// unsigned-атрибут id-aa-signatureTimeStampToken (OID 1.2.840.113549.1.9.16.2.14)
// - структурно, без обращения к KalkanCrypt. Аналог того, что в Java делает
// tspService.info(...) (см. CmsService.java) - тоже чистый ASN.1-разбор
// вложенного токена, не нативный вызов.
//
// Подпись самого TSP-токена намеренно не проверяется (как и в Java-варианте,
// который используется в CmsService только для извлечения полей) - доверие к
// содержимому CMS обеспечивается основной проверкой подписи самого CMS.
package tsp

import (
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	"github.com/digitorus/pkcs7"
)

// OID id-aa-signatureTimeStampToken (RFC 3161 / RFC 5035).
const AttributeOID = "1.2.840.113549.1.9.16.2.14"

// Info - структурные поля TSTInfo, аналог kz.ncanode.dto.tsp.TspInfo (без
// JSON-обвязки - её добавляет вызывающий пакет).
type Info struct {
	SerialNumber     string
	GenTime          time.Time
	Policy           string
	Hash             string
	TSPHashAlgorithm string
}

var ErrNoSigners = errors.New("tsp: timestamp token CMS has no signers")

// Extract разбирает содержимое unsigned-атрибута (SET OF AttributeValue,
// см. attribute.Value у digitorus/pkcs7 - каждый элемент SET - это сам
// TimeStampToken, ContentInfo обёрнутый в CMS SignedData) и возвращает поля
// TSTInfo из eContent.
func Extract(attrValueSet []byte) (Info, error) {
	var member asn1.RawValue
	if _, err := asn1.Unmarshal(attrValueSet, &member); err != nil {
		return Info{}, err
	}

	p7, err := pkcs7.Parse(member.FullBytes)
	if err != nil {
		return Info{}, err
	}
	if len(p7.Signers) == 0 {
		return Info{}, ErrNoSigners
	}

	var info tstInfo
	if _, err := asn1.Unmarshal(p7.Content, &info); err != nil {
		return Info{}, err
	}

	return Info{
		SerialNumber:     hex.EncodeToString(info.SerialNumber.Bytes()),
		GenTime:          info.GenTime,
		Policy:           info.Policy.String(),
		Hash:             hex.EncodeToString(info.MessageImprint.HashedMessage),
		TSPHashAlgorithm: hashAlgorithmName(info.MessageImprint.HashAlgorithm.Algorithm.String()),
	}, nil
}

// tstInfo - RFC 3161 TSTInfo. Accuracy/Ordering/Nonce/TSA/Extensions не
// используются Java-стороной (см. CmsService.java - берутся только
// serialNumber/genTime/policy/tsa/hash/tspHashAlgorithm, а tsa сейчас не
// извлекается и здесь), но должны быть описаны (пусть и как RawValue с явным
// тегом), иначе декодер не сможет надёжно отличить их от соседних optional
// полей с похожими тегами.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       tstAccuracy   `asn1:"optional"`
	Ordering       bool          `asn1:"optional,default:false"`
	Nonce          *big.Int      `asn1:"optional"`
	TSA            asn1.RawValue `asn1:"optional,tag:0"`
	Extensions     asn1.RawValue `asn1:"optional,tag:1"`
}

type tstAccuracy struct {
	Seconds      int `asn1:"optional"`
	Milliseconds int `asn1:"optional,tag:0"`
	Microseconds int `asn1:"optional,tag:1"`
}

type messageImprint struct {
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// hashAlgorithmByOID - аналог KalkanUtil.getHashingAlgorithmByOID: та же
// (сознательно неполная - без ГОСТ-2015) таблица, что использует сам Java
// для tspHashAlgorithm. Значения сверены декомпиляцией
// kz/gov/pki/kalkan/tsp/TSPAlgorithms.class (provider-jar 0.7.5). Для
// незнакомого OID (например ГОСТ-2015, см. gost34311_2015-2016 у KNCA)
// возвращается "" - как и в Java, где HashMap.get(...) даёт null.
//
//nolint:gochecknoglobals
var hashAlgorithmByOID = map[string]string{
	"1.2.840.113549.2.5":     "MD5",
	"1.3.14.3.2.26":          "SHA1",
	"2.16.840.1.101.3.4.2.4": "SHA224",
	"2.16.840.1.101.3.4.2.1": "SHA256",
	"2.16.840.1.101.3.4.2.2": "SHA384",
	"2.16.840.1.101.3.4.2.3": "SHA512",
	"1.3.36.3.2.2":           "RIPEMD128",
	"1.3.36.3.2.1":           "RIPEMD160",
	"1.3.36.3.2.3":           "RIPEMD256",
	"1.3.6.1.4.1.6801.1.2.1": "GOST34311GT",
	"1.2.398.3.10.1.3.1":     "GOST34311",
}

func hashAlgorithmName(oid string) string {
	return hashAlgorithmByOID[oid]
}
