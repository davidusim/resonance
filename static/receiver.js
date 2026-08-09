(() => {
  "use strict";

  const CREDENTIAL_KEY = "resonance.deviceCredentials.v1";
  const byId = (id) => document.getElementById(id);
  let credentials = readCredentials();
  let socket = null;
  let reconnectTimer = null;
  let heartbeatTimer = null;
  let audioContext = null;
  let clockOffsetMs = 0;
  const activeSources = new Map();

  function readCredentials() {
    try { return JSON.parse(localStorage.getItem(CREDENTIAL_KEY)); }
    catch { return null; }
  }

  function setPill(label, kind = "") {
    const pill = byId("connection-pill");
    pill.className = `pill ${kind}`.trim();
    pill.innerHTML = `<span class="dot"></span> ${label}`;
  }

  function setStage(heading, detail, mode = "ready") {
    byId("status-heading").textContent = heading;
    byId("status-detail").textContent = detail;
    byId("status-symbol").textContent = mode === "alert" ? "!" : mode === "loading" ? "…" : "✓";
    byId("status-stage").classList.toggle("alerting", mode === "alert");
  }

  async function unlockAudio() {
    if (!audioContext) audioContext = new AudioContext({ latencyHint: "interactive" });
    await audioContext.resume();
    const silent = audioContext.createBuffer(1, 1, 22050);
    const source = audioContext.createBufferSource();
    source.buffer = silent;
    source.connect(audioContext.destination);
    source.start();
    byId("enable-audio").classList.add("hidden");
  }

  async function syncClock() {
    const samples = [];
    for (let index = 0; index < 5; index += 1) {
      const before = Date.now();
      const response = await fetch(`/api/time?sample=${index}`, { cache: "no-store" });
      const payload = await response.json();
      const after = Date.now();
      samples.push({ rtt: after - before, offset: payload.server_time_ms - ((before + after) / 2) });
    }
    samples.sort((left, right) => left.rtt - right.rtt);
    clockOffsetMs = samples[0].offset;
  }

  function deviceHeaders() {
    return {
      "X-Device-Id": credentials.device_id,
      "Authorization": `Bearer ${credentials.device_secret}`
    };
  }

  async function sha256(buffer) {
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  function sendAlertStatus(alertId, status, detail = "") {
    if (!socket || socket.readyState !== WebSocket.OPEN) return;
    socket.send(JSON.stringify({
      type: "alert.status",
      alert_id: alertId,
      status,
      detail: String(detail).slice(0, 240),
      client_time_ms: Date.now() + clockOffsetMs
    }));
  }

  async function prepareAlert(message) {
    if (activeSources.has(message.alert_id)) {
      sendAlertStatus(message.alert_id, "ready", "Alert was already scheduled");
      return;
    }
    if (!audioContext || audioContext.state !== "running") {
      byId("enable-audio").classList.remove("hidden");
      setStage("Audio needs a tap", "Enable audio now to receive this alert.", "alert");
      sendAlertStatus(message.alert_id, "error", "Audio context is not enabled");
      return;
    }
    setStage("Preparing alert", `Verifying ${message.track.name}…`, "loading");
    try {
      const response = await fetch(message.track.url, { headers: deviceHeaders(), cache: "no-store" });
      if (!response.ok) throw new Error(`Audio download failed (${response.status})`);
      const encoded = await response.arrayBuffer();
      const digest = await sha256(encoded);
      if (digest !== message.track.sha256) throw new Error("Audio integrity verification failed");
      const decoded = await audioContext.decodeAudioData(encoded.slice(0));
      const source = audioContext.createBufferSource();
      const gain = audioContext.createGain();
      gain.gain.value = 1;
      source.buffer = decoded;
      source.connect(gain).connect(audioContext.destination);
      const serverNow = Date.now() + clockOffsetMs;
      const delaySeconds = Math.max(0, (message.start_at_ms - serverNow) / 1000);
      const scheduledFor = audioContext.currentTime + delaySeconds;
      source.start(scheduledFor);
      const playback = { source, startTimer: null, stopped: false };
      playback.startTimer = window.setTimeout(() => {
        if (!playback.stopped) sendAlertStatus(message.alert_id, "playing");
      }, delaySeconds * 1000);
      activeSources.set(message.alert_id, playback);
      sendAlertStatus(message.alert_id, "ready");
      source.addEventListener("ended", () => {
        window.clearTimeout(playback.startTimer);
        activeSources.delete(message.alert_id);
        if (!playback.stopped) {
          sendAlertStatus(message.alert_id, "completed");
          if (!activeSources.size) setStage("Standing by", "The alert finished. The trusted channel remains connected.");
        }
      });
      setStage("Emergency alert", `${message.track.name} · synchronized playback`, "alert");
    } catch (error) {
      setStage("Alert could not play", error.message, "alert");
      sendAlertStatus(message.alert_id, "error", error.message);
    }
  }

  function stopAlert(alertId) {
    const playback = activeSources.get(alertId);
    if (playback) {
      playback.stopped = true;
      window.clearTimeout(playback.startTimer);
      try { playback.source.stop(); } catch { /* already stopped */ }
      activeSources.delete(alertId);
    }
    sendAlertStatus(alertId, "stopped");
    if (!activeSources.size) setStage("Standing by", "Stop signal received. The trusted channel remains connected.");
  }

  function connect() {
    if (!credentials) return;
    clearTimeout(reconnectTimer);
    setPill("Connecting", "warning");
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    socket = new WebSocket(`${protocol}//${location.host}/ws/receiver`);
    socket.addEventListener("open", () => {
      socket.send(JSON.stringify({
        type: "auth",
        device_id: credentials.device_id,
        device_secret: credentials.device_secret
      }));
    });
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (message.type === "auth.ok") {
        setPill("Connected", "online");
        setStage("Standing by", `Receiver “${credentials.name}” is connected.`);
        clearInterval(heartbeatTimer);
        heartbeatTimer = setInterval(() => {
          if (socket.readyState === WebSocket.OPEN) {
            socket.send(JSON.stringify({ type: "ping", client_time_ms: Date.now() }));
          }
        }, 20000);
      } else if (message.type === "alert.prepare") {
        prepareAlert(message);
      } else if (message.type === "alert.stop") {
        stopAlert(message.alert_id);
      }
    });
    socket.addEventListener("close", (event) => {
      clearInterval(heartbeatTimer);
      if (!credentials) return;
      if (event.code === 4401 || event.code === 4003) {
        setPill("Access revoked", "error");
        setStage("Enrollment expired", "This receiver must be enrolled again.", "alert");
        return;
      }
      setPill("Reconnecting", "warning");
      reconnectTimer = setTimeout(connect, 2500);
    });
    socket.addEventListener("error", () => setPill("Connection interrupted", "error"));
  }

  async function startReceiver() {
    byId("enrollment-card").classList.add("hidden");
    byId("receiver-card").classList.remove("hidden");
    try {
      await unlockAudio();
      await syncClock();
      connect();
    } catch (error) {
      byId("enable-audio").classList.remove("hidden");
      setStage("Audio needs a tap", error.message, "loading");
      connect();
    }
  }

  byId("enrollment-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = byId("device-name").value.trim();
    const code = byId("enrollment-code").value.trim();
    const message = byId("enrollment-message");
    try {
      message.textContent = "Enrolling trusted receiver…";
      message.className = "message";
      await unlockAudio();
      const response = await fetch("/api/devices/enroll", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, code })
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || "Enrollment failed");
      credentials = payload;
      localStorage.setItem(CREDENTIAL_KEY, JSON.stringify(credentials));
      await syncClock();
      byId("enrollment-card").classList.add("hidden");
      byId("receiver-card").classList.remove("hidden");
      connect();
    } catch (error) {
      message.textContent = error.message;
      message.className = "message error";
    }
  });

  byId("enable-audio").addEventListener("click", async () => {
    try {
      await unlockAudio();
      setStage("Standing by", "Audio is enabled and the trusted channel is connected.");
    } catch (error) {
      setStage("Audio unavailable", error.message, "alert");
    }
  });

  byId("reset-device").addEventListener("click", () => {
    if (!window.confirm("Remove this receiver’s credentials from this browser?")) return;
    credentials = null;
    localStorage.removeItem(CREDENTIAL_KEY);
    clearTimeout(reconnectTimer);
    clearInterval(heartbeatTimer);
    if (socket) socket.close();
    location.reload();
  });

  if (credentials?.device_id && credentials?.device_secret) startReceiver();
})();
