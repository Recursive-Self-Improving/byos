(() => {
  "use strict";

  const copyButton = document.querySelector("[data-copy-target]");
  if (copyButton) {
    copyButton.addEventListener("click", async () => {
      const target = document.getElementById(copyButton.dataset.copyTarget || "");
      const status = document.querySelector("[data-copy-status]");
      if (!target || !status) return;
      const value = target.textContent || "";
      try {
        await navigator.clipboard.writeText(value);
        status.textContent = "API key copied. Store it in your secret manager now.";
      } catch {
        const selection = window.getSelection();
        const range = document.createRange();
        range.selectNodeContents(target);
        selection.removeAllRanges();
        selection.addRange(range);
        status.textContent = "Copy was blocked. The key text is selected for manual copying.";
      }
    });
  }

  const providerSelect = document.querySelector("[data-oauth-provider]");
  const providerStart = document.querySelector("[data-oauth-start]");
  if (providerSelect && providerStart) {
    const providerLabels = { xai: "xAI", devin: "Devin" };
    const updateProviderStart = () => {
      const label = providerLabels[providerSelect.value] || "provider";
      providerStart.textContent = `Start ${label} connection`;
    };
    providerSelect.addEventListener("change", updateProviderStart);
    updateProviderStart();
  }

  const flow = document.querySelector("[data-oauth-flow]");
  if (!flow) return;

  const statusNode = flow.querySelector("[data-oauth-status]");
  const countdownNode = flow.querySelector("[data-oauth-countdown]");
  const statusURL = flow.dataset.statusUrl || "";
  const expiresAt = Date.parse(flow.dataset.expiresAt || "");
  const configuredDelay = Number(flow.dataset.pollAfter || 2000);
  const pollDelay = Math.min(30000, Math.max(1000, configuredDelay));
  const terminal = new Set(["completed", "cancelled", "denied", "expired", "failed"]);
  let stopped = false;
  let countdownTimer;
  let pollTimer;

  const statusLabels = {
    pending: "Waiting for approval",
    completed: "Connected. Opening account…",
    cancelled: "Connection cancelled",
    denied: "Authorization denied",
    expired: "Device code expired",
    failed: "Connection failed"
  };

  function stop() {
    stopped = true;
    window.clearInterval(countdownTimer);
    window.clearTimeout(pollTimer);
  }

  function updateCountdown() {
    if (!countdownNode || !Number.isFinite(expiresAt)) return;
    const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
    const minutes = Math.floor(remaining / 60);
    const seconds = String(remaining % 60).padStart(2, "0");
    countdownNode.textContent = `${minutes}:${seconds}`;
  }

  async function poll() {
    if (stopped || !statusURL) return;
    try {
      const response = await fetch(statusURL, {
        method: "GET",
        headers: { Accept: "application/json" },
        cache: "no-store",
        credentials: "same-origin"
      });
      if (!response.ok) throw new Error("status unavailable");
      const payload = await response.json();
      const state = typeof payload.status === "string" ? payload.status : "failed";
      if (statusNode) {
        const label = statusLabels[state] || statusLabels.failed;
        statusNode.textContent = payload.message ? `${label}: ${payload.message}` : label;
      }
      if (state === "completed" && typeof payload.account_url === "string") {
        const target = new URL(payload.account_url, window.location.origin);
        if (target.origin === window.location.origin && target.pathname.startsWith("/admin/accounts/")) {
          stop();
          window.location.assign(target.href);
          return;
        }
      }
      if (terminal.has(state)) {
        stop();
        return;
      }
      const nextDelay = Number(payload.poll_after_ms);
      pollTimer = window.setTimeout(poll, Number.isFinite(nextDelay) ? Math.min(30000, Math.max(1000, nextDelay)) : pollDelay);
    } catch {
      if (statusNode) statusNode.textContent = "Connection status interrupted. Retrying…";
      pollTimer = window.setTimeout(poll, pollDelay);
    }
  }

  updateCountdown();
  countdownTimer = window.setInterval(updateCountdown, 1000);
  poll();
})();
