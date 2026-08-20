package cms

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/ncanode-kz/NCANode-Go/internal/dto"
	"github.com/ncanode-kz/NCANode-Go/internal/testutil"
)

func TestZZDebugSignError(t *testing.T) {
	a := testutil.NewApp(t)

	data := base64.StdEncoding.EncodeToString([]byte("cms handler test"))

	_, err := sign(a, dto.CmsCreateRequest{
		Data:    data,
		Signers: []dto.SignerRequest{signerReq(t, "individual/valid/individual_valid.p12")},
	}, false)
	if err != nil {
		t.Errorf("DEBUG top error: %v", err)
		t.Errorf("DEBUG unwrapped: %v", errors.Unwrap(err))
	} else {
		t.Error("DEBUG no error")
	}
}
