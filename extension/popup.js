let activeTab = null;
let gatewayConfigured = false;

async function load() {
  [activeTab] = await chrome.tabs.query({active: true, currentWindow: true});
  document.querySelector("#tab").textContent = activeTab?.title || activeTab?.url || "No active tab";
  const stored = await chrome.storage.local.get("gatewayURL");
  if (stored.gatewayURL) {
    gatewayConfigured = true;
    document.querySelector("#gateway").textContent = stored.gatewayURL;
  }
  await refreshStatus();
}

async function refreshStatus() {
  const state = await chrome.runtime.sendMessage({type: "status"});
  const status = document.querySelector("#status");
  status.textContent = state.message;
  status.className = `status ${state.connected ? "connected" : state.configured ? "" : "error"}`;
  if (!gatewayConfigured) {
    status.textContent = "Configure a gateway before pairing.";
    status.className = "status error";
  }
  document.querySelector("#pair").hidden = state.connected || !gatewayConfigured;
  document.querySelector("#disconnect").hidden = !state.configured;
}

document.querySelector("#pair").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.target.querySelector("button");
  button.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({
      type: "pair",
      pairingCode: document.querySelector("#code").value,
      tabId: activeTab.id,
    });
    if (!result.ok) throw new Error(result.error);
    await new Promise((resolve) => setTimeout(resolve, 300));
    await refreshStatus();
  } catch (error) {
    const status = document.querySelector("#status");
    status.textContent = error.message;
    status.className = "status error";
  } finally {
    button.disabled = false;
  }
});

document.querySelector("#settings").addEventListener("click", () => chrome.runtime.openOptionsPage());

document.querySelector("#disconnect").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({type: "disconnect"});
  await refreshStatus();
});

load();
