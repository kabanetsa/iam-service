package oauth

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"iam-service/internal/api/respond"
	"iam-service/internal/service"
)

// DocumentsHandler serves the OpenID Connect discovery document and the JWKS.
type DocumentsHandler struct {
	oidc *service.OIDCService
}

// NewDocumentsHandler builds the documents handler.
func NewDocumentsHandler(oidc *service.OIDCService) *DocumentsHandler {
	return &DocumentsHandler{oidc: oidc}
}

// Discovery serves GET /.well-known/openid-configuration.
func (h *DocumentsHandler) Discovery(c *gin.Context) {
	c.Header("Cache-Control", "public, max-age=3600")
	c.JSON(http.StatusOK, h.oidc.Discovery())
}

// JWKS serves GET /.well-known/jwks.json.
func (h *DocumentsHandler) JWKS(c *gin.Context) {
	payload, err := h.oidc.JWKS()
	if err != nil {
		respond.Error(c, err)
		return
	}
	// Keys are cached aggressively: rotation is rare and clients must be able to
	// verify tokens offline.
	c.Header("Cache-Control", "public, max-age=3600")
	c.Data(http.StatusOK, "application/json; charset=utf-8", payload)
}

// ProviderMetadata is a helper for tests and documentation: it returns the
// discovery document as a typed map.
func (h *DocumentsHandler) ProviderMetadata() (map[string]any, error) {
	payload, err := json.Marshal(h.oidc.Discovery())
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}
