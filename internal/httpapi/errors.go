package httpapi

import "net/http"

// AppError - типизированная ошибка с HTTP-статусом, аналог иерархии
// ApplicationException/ClientException/ServerException/NoSignaturesFoundException
// в Java NCANode.
type AppError struct {
	StatusCode int
	Msg        string
	Cause      error
}

func (e *AppError) Error() string { return e.Msg }
func (e *AppError) Unwrap() error { return e.Cause }

// ClientError - аналог kz.ncanode.exception.ClientException (400): неверный
// запрос со стороны клиента.
func ClientError(msg string, cause error) error {
	return &AppError{StatusCode: http.StatusBadRequest, Msg: msg, Cause: cause}
}

// ServerError - аналог kz.ncanode.exception.ServerException (500): ошибка на
// стороне сервиса при обработке в остальном корректного запроса.
func ServerError(msg string, cause error) error {
	return &AppError{StatusCode: http.StatusInternalServerError, Msg: msg, Cause: cause}
}

// NotFoundError - аналог kz.ncanode.exception.NoSignaturesFoundException (404).
func NotFoundError(msg string, cause error) error {
	return &AppError{StatusCode: http.StatusNotFound, Msg: msg, Cause: cause}
}
