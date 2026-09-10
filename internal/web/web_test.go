package web

import (
	"bytes"
	"strings"
	"testing"
)

func TestTemplatesParse(t *testing.T) {
	pages, err := Templates()
	if err != nil {
		t.Fatalf("templates: %v", err)
	}
	for _, name := range []string{PageLogin, PageConsent, PageError} {
		if _, ok := pages[name]; !ok {
			t.Errorf("page %s was not parsed", name)
		}
	}
}

func TestRenderLoginPage(t *testing.T) {
	pages, err := Templates()
	if err != nil {
		t.Fatalf("templates: %v", err)
	}

	var buf bytes.Buffer
	err = pages.Render(&buf, PageLogin, map[string]any{
		"Title":         "Вход",
		"ClientName":    "ERP Lite (web)",
		"InteractionID": "interaction-1",
		"CSRFToken":     "csrf-1",
		"Email":         "user@example.com",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}

	body := buf.String()
	for _, want := range []string{
		`name="interaction" value="interaction-1"`,
		`name="csrf_token" value="csrf-1"`,
		`name="email"`,
		`name="password"`,
		"ERP Lite (web)",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page is missing %q", want)
		}
	}
}

func TestRenderConsentPageListsScopes(t *testing.T) {
	pages, err := Templates()
	if err != nil {
		t.Fatalf("templates: %v", err)
	}

	var buf bytes.Buffer
	if err := pages.Render(&buf, PageConsent, map[string]any{
		"Title":         "Согласие",
		"ClientName":    "ERP Lite (web)",
		"InteractionID": "interaction-2",
		"CSRFToken":     "csrf-2",
		"UserEmail":     "user@example.com",
		"Scopes":        []string{"Адрес электронной почты", "Доступ без повторного входа"},
	}); err != nil {
		t.Fatalf("render: %v", err)
	}

	body := buf.String()
	for _, want := range []string{"Адрес электронной почты", "Доступ без повторного входа", `value="deny"`, `value="allow"`} {
		if !strings.Contains(body, want) {
			t.Errorf("consent page is missing %q", want)
		}
	}
}

func TestRenderEscapesUntrustedValues(t *testing.T) {
	pages, err := Templates()
	if err != nil {
		t.Fatalf("templates: %v", err)
	}

	var buf bytes.Buffer
	if err := pages.Render(&buf, PageError, map[string]any{
		"Title":     "Ошибка",
		"Message":   `<script>alert(1)</script>`,
		"ErrorCode": "invalid_request",
	}); err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(buf.String(), "<script>alert(1)</script>") {
		t.Fatal("html/template did not escape the message")
	}
}

func TestRenderUnknownPageFails(t *testing.T) {
	pages, err := Templates()
	if err != nil {
		t.Fatalf("templates: %v", err)
	}
	var buf bytes.Buffer
	if err := pages.Render(&buf, "nope.html", nil); err == nil {
		t.Fatal("rendering an unknown page must fail")
	}
}
