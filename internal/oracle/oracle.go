//go:build oracle

// Package oracle - клиент для ручной сверки ответов NCANode-Go с эталонным
// Java NCANode, поднятым локально (см. gokalkan/internal/oracle/README.md -
// тот же принцип: тестовые URL test.pki.gov.kz, порт 14579). Собирается
// только с тегом "oracle", в обычный go test ./... не попадает.
package oracle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:14579"
	}
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type M = map[string]any

func (c *Client) Post(path string, req any) (M, error) {
	var body io.Reader
	if req != nil {
		b, err := json.Marshal(req)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		body = bytes.NewReader(b)
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out M
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return out, nil
}

func (c *Client) Healthy() bool {
	resp, err := c.HTTP.Get(c.BaseURL + "/actuator/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var out struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}

	return out.Status == "UP"
}
