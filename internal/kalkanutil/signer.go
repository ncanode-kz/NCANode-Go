// Package kalkanutil - мелкие переиспользуемые операции над gokalkan.Client,
// общие для нескольких service/* пакетов.
package kalkanutil

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/ncanode-kz/gokalkan"
)

// LoadSigner декодирует base64 PKCS12, загружает его в cli как текущий ключ
// и возвращает PEM-сертификат подписанта. alias - опциональный SignerRequest.KeyAlias
// (см. KC_LoadKeyStore/KC_GetCertificatesList) - для PKCS12 с несколькими
// ключами выбирает нужный; для типичного PKCS12 с одним ключом можно не
// передавать (пустой alias означает дефолтный, как и раньше).
func LoadSigner(cli *gokalkan.Client, keyB64, password string, alias ...string) (certPEM string, err error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}

	if err := cli.LoadKeyStoreFromBytes(key, password, alias...); err != nil {
		return "", err
	}

	return cli.X509ExportCertificateFromStore("")
}

// PEMFromDER оборачивает сырые DER-байты сертификата в PEM - формат, который
// принимают native-вызовы через gokalkan (см. также DERFromPEM).
func PEMFromDER(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// PEMFromBase64Body оборачивает в PEM-заголовки base64-текст сертификата,
// уже перенесённый (с переводами строк), но без "-----BEGIN/END-----" -
// именно в таком виде отдаёт сертификат ckalkan.GetCertFromXML, в отличие от
// большинства других вызовов (X509ExportCertificateFromStore и т.п.),
// возвращающих готовый PEM или сырой DER.
func PEMFromBase64Body(body []byte) string {
	return "-----BEGIN CERTIFICATE-----\n" + string(body) + "\n-----END CERTIFICATE-----\n"
}

// DERFromPEMOrDER возвращает сырые DER-байты, принимая на вход как PEM, так
// и уже "голый" DER (некоторые нативные вызовы, например
// X509ExportCertificateFromStore, отдают PEM; входные данные из запросов
// клиентов Java обычно приходят как base64(DER) без PEM-обёртки).
func DERFromPEMOrDER(data []byte) []byte {
	if block, _ := pem.Decode(data); block != nil {
		return block.Bytes
	}
	return data
}

// StripWhitespace убирает любые пробельные символы - Java перед декодированием
// base64 сертификатов из запроса делает certBase64.replaceAll("\\s", "").
func StripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \t\r\n", r) {
			return -1
		}
		return r
	}, s)
}
