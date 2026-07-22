package web

import (
	"net/http"
	"strings"
	"unicode/utf8"
)

type accountsPage struct {
	layoutData
	Accounts       []AccountSummary
	ProviderFilter Provider
}

func (h *Handler) handleAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	filter, ok := providerFilter(r)
	if !ok {
		h.renderError(w, r, http.StatusBadRequest, "Choose xAI or Devin as the provider filter.")
		return
	}
	accounts, err := h.services.Accounts.List(r.Context())
	if err == nil {
		accounts = filterAccounts(accounts, filter)
	}
	data := accountsPage{layoutData: h.layout(r, "Accounts", "accounts"), Accounts: accounts, ProviderFilter: filter}
	status := http.StatusOK
	if err != nil {
		data.LoadError = "Accounts could not be loaded."
		status = http.StatusServiceUnavailable
	}
	h.render(w, "accounts", status, data)
}

type accountPage struct {
	layoutData
	Account     AccountDetail
	ActionError string
}

func (h *Handler) handleAccount(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	h.renderAccount(w, r, id, http.StatusOK, "")
}

func (h *Handler) renderAccount(w http.ResponseWriter, r *http.Request, id string, status int, actionError string) {
	account, err := h.services.Accounts.Get(r.Context(), id)
	if err != nil {
		if isNotFound(err) {
			h.renderError(w, r, http.StatusNotFound, "Account not found.")
		} else {
			h.renderError(w, r, http.StatusServiceUnavailable, "The account could not be loaded.")
		}
		return
	}
	account.Models = collapseAccountModelAliases(account.ID, account.Models)
	data := accountPage{layoutData: h.layout(r, displayLabel(account.Label), "accounts"), Account: account, ActionError: actionError}
	h.render(w, "account", status, data)
}

func (h *Handler) handleAccountLabel(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderAccount(w, r, id, http.StatusBadRequest, "The label form could not be read.")
		return
	}
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if label == "" || utf8.RuneCountInString(label) > 100 {
		h.renderAccount(w, r, id, http.StatusBadRequest, "Enter a label between 1 and 100 characters.")
		return
	}
	if err := h.services.Accounts.Update(r.Context(), id, AccountUpdate{Label: &label}); err != nil {
		h.renderMutationError(w, r, err, "Account settings could not be updated.")
		return
	}
	h.redirect(w, r, accountURL(id)+"?notice=account-updated")
}

func (h *Handler) handleAccountEnabled(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := r.ParseForm(); err != nil {
		h.renderAccount(w, r, id, http.StatusBadRequest, "The account form could not be read.")
		return
	}
	var enabled bool
	switch r.PostForm.Get("enabled") {
	case "true":
		enabled = true
	case "false":
		enabled = false
	default:
		h.renderAccount(w, r, id, http.StatusBadRequest, "Choose whether the account is enabled.")
		return
	}
	if err := h.services.Accounts.Update(r.Context(), id, AccountUpdate{Enabled: &enabled}); err != nil {
		h.renderMutationError(w, r, err, "Account settings could not be updated.")
		return
	}
	h.redirect(w, r, accountURL(id)+"?notice=account-updated")
}

func (h *Handler) handleAccountRefresh(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := h.services.Accounts.Refresh(r.Context(), id); err != nil {
		h.renderMutationError(w, r, err, "The account refresh could not be started.")
		return
	}
	h.redirect(w, r, accountURL(id)+"?notice=account-refreshed")
}

func (h *Handler) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAuthentication(w, r); !ok {
		return
	}
	id, ok := resourceID(r.PathValue("id"))
	if !ok {
		h.renderError(w, r, http.StatusNotFound, "Account not found.")
		return
	}
	if err := r.ParseForm(); err != nil || r.PostForm.Get("confirm") != "delete" {
		h.renderAccount(w, r, id, http.StatusBadRequest, "Confirm account deletion before continuing.")
		return
	}
	if err := h.services.Accounts.Delete(r.Context(), id); err != nil {
		h.renderMutationError(w, r, err, "The account could not be deleted.")
		return
	}
	h.redirect(w, r, "/admin/accounts?notice=account-deleted")
}

func providerFilter(r *http.Request) (Provider, bool) {
	value := r.URL.Query().Get("provider")
	if value == "" {
		return "", true
	}
	filter := Provider(value)
	return filter, filter.Valid()
}

func filterAccounts(values []AccountSummary, filter Provider) []AccountSummary {
	if filter == "" {
		return values
	}
	filtered := make([]AccountSummary, 0, len(values))
	for _, value := range values {
		if value.Provider == filter {
			filtered = append(filtered, value)
		}
	}
	return filtered
}
