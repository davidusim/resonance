(() => {
  "use strict";

  let adminToken = sessionStorage.getItem("resonance.adminToken") || "";
  let activeAlertId = null;
  let alertPollTimer = null;
  let alertPollAttempts = 0;

  const byId = (id) => document.getElementById(id);
  const statusPill = byId("api-status");
  const controls = ["refresh", "create-code", "audio-file", "upload-button"];

  function setMessage(id, message, kind = "") {
    const element = byId(id);
    element.textContent = message;
    element.className = `message ${kind}`.trim();
  }

  function setUnlocked(unlocked) {
    controls.forEach((id) => { byId(id).disabled = !unlocked; });
    statusPill.className = `pill ${unlocked ? "online" : ""}`;
    statusPill.innerHTML = `<span class="dot"></span> ${unlocked ? "Coordinator ready" : "Locked"}`;
  }

  async function api(path, options = {}) {
    const headers = new Headers(options.headers || {});
    headers.set("Authorization", `Bearer ${adminToken}`);
    if (options.body && !(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
    const response = await fetch(path, { ...options, headers, cache: "no-store" });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || `Request failed (${response.status})`);
    }
    return response.json();
  }

  const formatTime = (value) => value ? new Date(value).toLocaleString() : "Never";

  async function refresh() {
    const [status, devices, tracks] = await Promise.all([
      api("/api/status"), api("/api/devices"), api("/api/tracks")
    ]);
    byId("connected-count").textContent = status.connected_receivers;
    byId("device-count").textContent = devices.devices.filter((item) => !item.revoked).length;
    renderDevices(devices.devices);
    renderTracks(tracks.tracks);
    renderAlertProgress(status.alerts);
    setUnlocked(true);
  }

  function renderAlertProgress(alerts) {
    if (!activeAlertId) {
      const candidate = alerts.find((alert) => {
        const terminal = alert.completed_count + alert.stopped_count + alert.error_count;
        return !alert.stopped_at && alert.delivered_count > 0 && terminal < alert.delivered_count;
      });
      if (candidate) activeAlertId = candidate.id;
    }
    const alert = alerts.find((item) => item.id === activeAlertId);
    if (!alert) return;

    byId("alert-progress").classList.remove("hidden");
    byId("stop-alert").classList.remove("hidden");
    byId("ready-count").textContent = alert.ready_count;
    byId("playing-count").textContent = alert.playing_count;
    byId("completed-count").textContent = alert.completed_count;
    byId("error-count").textContent = alert.error_count;

    const errorDevices = alert.receipts
      .filter((receipt) => receipt.status === "error")
      .map((receipt) => receipt.device_name)
      .join(", ");
    const detail = errorDevices ? ` Errors: ${errorDevices}.` : "";
    setMessage(
      "alert-message",
      `${alert.track_name}: ${alert.ready_count} ready, ${alert.playing_count} playing, ` +
        `${alert.completed_count} completed of ${alert.delivered_count} dispatched.${detail}`,
      alert.error_count ? "error" : "ok"
    );

    const terminal = alert.completed_count + alert.stopped_count + alert.error_count;
    if (alert.delivered_count > 0 && terminal >= alert.delivered_count) stopAlertPolling();
  }

  function startAlertPolling() {
    stopAlertPolling();
    alertPollAttempts = 0;
    alertPollTimer = window.setInterval(() => {
      alertPollAttempts += 1;
      refresh().catch((error) => setMessage("alert-message", error.message, "error"));
      if (alertPollAttempts >= 40) stopAlertPolling();
    }, 1500);
  }

  function stopAlertPolling() {
    if (alertPollTimer) window.clearInterval(alertPollTimer);
    alertPollTimer = null;
  }

  function renderDevices(devices) {
    const list = byId("device-list");
    list.replaceChildren();
    if (!devices.length) {
      list.innerHTML = '<div class="empty">No receivers enrolled yet.</div>';
      return;
    }
    devices.forEach((device) => {
      const item = document.createElement("div");
      item.className = "list-item";
      const info = document.createElement("div");
      const state = device.revoked ? "Revoked" : device.connected ? "Connected" : "Offline";
      info.innerHTML = `<strong></strong><small></small>`;
      info.querySelector("strong").textContent = device.name;
      info.querySelector("small").textContent = `${state} · Last seen ${formatTime(device.last_seen_at)}`;
      item.append(info);
      if (!device.revoked) {
        const revoke = document.createElement("button");
        revoke.className = "secondary small";
        revoke.textContent = "Revoke";
        revoke.addEventListener("click", async () => {
          if (!window.confirm(`Revoke ${device.name}? This receiver will need a new enrollment code.`)) return;
          await api(`/api/devices/${device.id}`, { method: "DELETE" });
          await refresh();
        });
        item.append(revoke);
      }
      list.append(item);
    });
  }

  function renderTracks(tracks) {
    const list = byId("track-list");
    list.replaceChildren();
    if (!tracks.length) {
      list.innerHTML = '<div class="empty">No audio uploaded yet.</div>';
      return;
    }
    tracks.forEach((track) => {
      const item = document.createElement("div");
      item.className = "list-item";
      const info = document.createElement("div");
      info.innerHTML = `<strong></strong><small></small>`;
      info.querySelector("strong").textContent = track.name;
      info.querySelector("small").textContent = `${(track.size_bytes / 1024 / 1024).toFixed(2)} MB · SHA-256 ${track.sha256.slice(0, 12)}…`;
      const play = document.createElement("button");
      play.className = "primary small";
      play.textContent = "Dispatch alert";
      play.addEventListener("click", () => dispatchAlert(track));
      item.append(info, play);
      list.append(item);
    });
  }

  async function dispatchAlert(track) {
    if (!window.confirm(`Dispatch “${track.name}” to every connected receiver?`)) return;
    try {
      const result = await api("/api/alerts", {
        method: "POST",
        body: JSON.stringify({ track_id: track.id })
      });
      activeAlertId = result.alert_id;
      byId("stop-alert").classList.remove("hidden");
      setMessage("alert-message", `Dispatched to ${result.delivered} receiver(s). Scheduled for ${formatTime(result.start_at_ms)}.`, "ok");
      await refresh();
      startAlertPolling();
    } catch (error) {
      setMessage("alert-message", error.message, "error");
    }
  }

  byId("auth-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    adminToken = byId("admin-token").value.trim();
    try {
      await refresh();
      sessionStorage.setItem("resonance.adminToken", adminToken);
      setMessage("auth-message", "Dashboard unlocked for this browser tab.", "ok");
    } catch (error) {
      adminToken = "";
      sessionStorage.removeItem("resonance.adminToken");
      setUnlocked(false);
      setMessage("auth-message", error.message, "error");
    }
  });

  byId("refresh").addEventListener("click", () => refresh().catch((error) => setMessage("auth-message", error.message, "error")));

  byId("create-code").addEventListener("click", async () => {
    try {
      const enrollment = await api("/api/enrollments", { method: "POST", body: "{}" });
      const code = byId("enrollment-code");
      code.textContent = enrollment.code;
      code.classList.remove("hidden");
      setMessage("enrollment-message", `Expires ${formatTime(enrollment.expires_at)}.`, "ok");
    } catch (error) {
      setMessage("enrollment-message", error.message, "error");
    }
  });

  byId("upload-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const file = byId("audio-file").files[0];
    if (!file) return;
    const form = new FormData();
    form.append("file", file);
    try {
      setMessage("upload-message", "Uploading and hashing…");
      const track = await api("/api/tracks", { method: "POST", body: form });
      event.target.reset();
      setMessage("upload-message", `${track.name} is ready.`, "ok");
      await refresh();
    } catch (error) {
      setMessage("upload-message", error.message, "error");
    }
  });

  byId("stop-alert").addEventListener("click", async () => {
    if (!activeAlertId) return;
    try {
      const result = await api(`/api/alerts/${activeAlertId}/stop`, { method: "POST" });
      setMessage("alert-message", `Stop signal delivered to ${result.delivered} receiver(s).`, "ok");
      activeAlertId = null;
      stopAlertPolling();
      byId("stop-alert").classList.add("hidden");
      byId("alert-progress").classList.add("hidden");
    } catch (error) {
      setMessage("alert-message", error.message, "error");
    }
  });

  if (adminToken) {
    byId("admin-token").value = adminToken;
    refresh().catch(() => {
      sessionStorage.removeItem("resonance.adminToken");
      setUnlocked(false);
    });
  }
})();
