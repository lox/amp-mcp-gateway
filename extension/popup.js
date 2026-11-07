let activeTab = null;
let gatewayConfigured = false;
let gatewayURL = "";
let actionPending = false;

async function load() {
  [activeTab] = await chrome.tabs.query({active: true, currentWindow: true});
  document.querySelector("#tab").textContent = activeTab?.title || activeTab?.url || "No active tab";
  const stored = await chrome.storage.local.get("gatewayURL");
  if (stored.gatewayURL) {
    gatewayConfigured = true;
    gatewayURL = stored.gatewayURL;
    document.querySelector("#gateway").textContent = stored.gatewayURL;
  }
  await refreshStatus();
}

async function refreshStatus() {
  const state = await chrome.runtime.sendMessage({type: "status"});
  const status = document.querySelector("#status");
  status.textContent = state.connected && state.sharedTab ? `Sharing ${state.sharedTab.title || state.sharedTab.url}` : state.message;
  status.className = `status ${state.connected ? "connected" : state.registered || state.configured ? "" : "error"}`;
  if (!gatewayConfigured) {
    status.textContent = "Configure a gateway before registering this browser.";
    status.className = "status error";
  }
  const connecting = state.status === "connecting";
  const registration = document.querySelector("#registration");
  registration.hidden = !gatewayConfigured;
  registration.querySelector("summary").hidden = !state.registered;
  if (!state.registered) registration.open = true;
  document.querySelector("#pair button[type=submit]").disabled = connecting;
  const browser = document.querySelector("#browser");
  browser.hidden = !state.registered;
  browser.textContent = `Browser: ${state.browserName}`;
  const share = document.querySelector("#share");
  share.hidden = !state.registered || state.sharedTab?.id === activeTab?.id;
  share.disabled = connecting || actionPending || !/^https?:/.test(activeTab?.url || "");
  share.textContent = state.sharedTab ? "Share this tab instead" : "Share this tab";
  document.querySelector("#disconnect").hidden = !state.configured;
  document.querySelector("#manage").hidden = !state.registered;
}

document.querySelector("#pair").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.target.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({
      type: "pair",
      pairingCode: document.querySelector("#code").value,
    });
    if (!result.ok) throw new Error(result.error);
    await refreshStatus();
  } catch (error) {
    const status = document.querySelector("#status");
    status.textContent = error.message;
    status.className = "status error";
    button.disabled = false;
  }
});

document.querySelector("#settings").addEventListener("click", () => chrome.runtime.openOptionsPage());

for (const id of ["setup", "manage"]) {
  document.querySelector(`#${id}`).addEventListener("click", () => chrome.tabs.create({url: `${gatewayURL}/integrations/chrome`}));
}

document.querySelector("#share").addEventListener("click", async () => {
  actionPending = true;
  document.querySelector("#share").disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({type: "share", tabId: activeTab.id});
    if (!result.ok) throw new Error(result.error);
    actionPending = false;
    await refreshStatus();
  } catch (error) {
    document.querySelector("#status").textContent = error.message;
    document.querySelector("#status").className = "status error";
    document.querySelector("#share").disabled = false;
  } finally {
    actionPending = false;
  }
});

document.querySelector("#disconnect").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({type: "disconnect"});
  await refreshStatus();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.registeredBrowser?.newValue) {
    document.querySelector("#registration").open = false;
    document.querySelector("#code").value = "";
  }
  if (area === "session" || area === "local") refreshStatus();
});

load();
