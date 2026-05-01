package oidc

import "time"

func (h *Handler) cleanupExpiredCodesLocked(now time.Time) {
	for code, session := range h.codes {
		if session.CodeExpireTime.Before(now) {
			delete(h.codes, code)
		}
	}
}

func (h *Handler) cleanupExpiredSessionsLocked(now time.Time) {
	for accessToken, session := range h.sessions {
		if !session.SessionExpireTime.IsZero() && session.SessionExpireTime.Before(now) {
			delete(h.sessions, accessToken)
		}
	}
}

func (h *Handler) putCode(code string, session *Session) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	h.cleanupExpiredCodesLocked(now)
	h.cleanupExpiredSessionsLocked(now)
	h.codes[code] = session
}

func (h *Handler) getCode(code string) (*Session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	h.cleanupExpiredCodesLocked(now)
	h.cleanupExpiredSessionsLocked(now)
	session, ok := h.codes[code]
	return session, ok
}

func (h *Handler) exchangeCode(code string) (*Session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	h.cleanupExpiredCodesLocked(now)
	h.cleanupExpiredSessionsLocked(now)

	session, ok := h.codes[code]
	if !ok {
		return nil, false
	}

	delete(h.codes, code)
	h.sessions[session.AccessToken] = session

	return session, true
}

func (h *Handler) getSession(accessToken string) (*Session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cleanupExpiredSessionsLocked(time.Now())
	session, ok := h.sessions[accessToken]
	return session, ok
}

func (h *Handler) revokeSession(accessToken string, clientID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cleanupExpiredSessionsLocked(time.Now())
	session, ok := h.sessions[accessToken]
	if !ok || session.ClientID != clientID {
		return false
	}

	delete(h.sessions, accessToken)
	return true
}
