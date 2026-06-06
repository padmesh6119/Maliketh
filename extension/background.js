// background script — bridges content/popup to the native host; attests origins
const HOST = "com.maliketh.host";

function nativeRequest(message) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendNativeMessage(HOST, message, (resp) => {
        if (chrome.runtime.lastError) {
          resolve({ ok: false, error: chrome.runtime.lastError.message });
        } else {
          resolve(resp || { ok: false, error: "empty response" });
        }
      });
    } catch (e) {
      resolve({ ok: false, error: String(e) });
    }
  });
}

function originFromUrl(url) {
  try {
    return new URL(url).origin;
  } catch (e) {
    return "";
  }
}

async function senderOrigin(sender) {
  if (sender && sender.tab && sender.url) {
    const o = originFromUrl(sender.url);
    if (o) return o;
  }
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab && tab.url ? originFromUrl(tab.url) : "";
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab || null;
}

function pendingKey(tabId) {
  return "pending:" + tabId;
}

async function setPending(tabId, data) {
  await chrome.storage.session.set({ [pendingKey(tabId)]: data });
  try {
    await chrome.action.setBadgeText({ tabId, text: "+" });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#b5179e" });
  } catch (e) {}
}

async function getPending(tabId) {
  const k = pendingKey(tabId);
  const got = await chrome.storage.session.get(k);
  return got[k] || null;
}

async function clearPending(tabId) {
  await chrome.storage.session.remove(pendingKey(tabId));
  try {
    await chrome.action.setBadgeText({ tabId, text: "" });
  } catch (e) {}
}

async function dispatch(msg, sender) {
  switch (msg.cmd) {
    case "status":
      return nativeRequest({ type: "status" });

    case "match": {
      const origin = await senderOrigin(sender);
      if (!origin) return { ok: false, error: "no origin" };
      return nativeRequest({ type: "match", origin });
    }

    case "fill": {
      const origin = await senderOrigin(sender);
      if (!origin || !msg.entryId) return { ok: false, error: "missing origin/entryId" };
      return nativeRequest({ type: "fill", entryId: msg.entryId, origin });
    }

    case "fillActive": {
      const tab = await activeTab();
      if (!tab) return { ok: false, error: "no active tab" };
      const origin = originFromUrl(tab.url);
      const resp = await nativeRequest({ type: "fill", entryId: msg.entryId, origin });
      if (resp.ok && resp.entry) {
        try {
          await chrome.tabs.sendMessage(tab.id, {
            cmd: "fillFields",
            username: resp.entry.username,
            password: resp.entry.password,
          });
        } catch (e) {
          return { ok: false, error: "no login form on page" };
        }
      }
      return resp;
    }

    case "matchActive": {
      const tab = await activeTab();
      if (!tab) return { ok: false, error: "no active tab" };
      return nativeRequest({ type: "match", origin: originFromUrl(tab.url) });
    }

    case "lock":
      return nativeRequest({ type: "lock" });

    case "unlock": {
      if (sender && sender.tab) return { ok: false, error: "unlock not allowed from a page" };
      if (!msg.password) return { ok: false, error: "missing password" };
      return nativeRequest({ type: "unlock", password: msg.password });
    }

    case "generate":
      return nativeRequest({ type: "generate", length: msg.length || 20, opts: msg.opts || {} });

    case "capture": {
      const origin = await senderOrigin(sender);
      if (!origin || !msg.password) return { ok: false, error: "missing origin/password" };
      return nativeRequest({ type: "capture", origin, username: msg.username || "", password: msg.password });
    }

    case "offerCapture": {
      const tabId = sender && sender.tab ? sender.tab.id : null;
      const origin = await senderOrigin(sender);
      if (tabId == null || !origin || !msg.password) return { ok: false };
      await setPending(tabId, { origin, username: msg.username || "", password: msg.password });
      return { ok: true };
    }

    case "getPending": {
      const tab = await activeTab();
      if (!tab) return { ok: true, pending: null };
      return { ok: true, pending: await getPending(tab.id) };
    }

    case "confirmCapture": {
      const tab = await activeTab();
      if (!tab) return { ok: false, error: "no active tab" };
      const pending = await getPending(tab.id);
      if (!pending) return { ok: false, error: "nothing to save" };
      const resp = await nativeRequest({
        type: "capture",
        origin: pending.origin,
        username: pending.username,
        password: pending.password,
      });
      if (resp.ok) await clearPending(tab.id);
      return resp;
    }

    case "dismissCapture": {
      const tab = await activeTab();
      if (tab) await clearPending(tab.id);
      return { ok: true };
    }

    default:
      return { ok: false, error: "unknown cmd" };
  }
}

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  dispatch(msg, sender).then(sendResponse);
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session.remove(pendingKey(tabId));
});
