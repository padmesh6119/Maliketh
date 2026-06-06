// popup script
function send(msg) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
      else resolve(resp || { ok: false });
    });
  });
}

const statusEl = document.getElementById("status");
const bodyEl = document.getElementById("body");
const captureEl = document.getElementById("capture");

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  Object.assign(e, attrs || {});
  for (const k of kids) e.append(k);
  return e;
}

async function renderCapture() {
  captureEl.innerHTML = "";
  const resp = await send({ cmd: "getPending" });
  const p = resp && resp.pending;
  if (!p) return;
  const box = el("div", { className: "capture" });
  box.append(el("div", { textContent: "Save this login?" , style: "font-weight:600" }));
  box.append(el("div", { className: "muted", textContent: (p.username || "(no username)") + " @ " + p.origin }));
  const acts = el("div", { className: "acts" });
  const save = el("button", { textContent: "Save" });
  const skip = el("button", { className: "ghost", textContent: "Dismiss" });
  save.onclick = async () => {
    save.disabled = true;
    const r = await send({ cmd: "confirmCapture" });
    if (r.ok) { await renderCapture(); await refresh(); }
    else { save.disabled = false; alert(r.error || "save failed"); }
  };
  skip.onclick = async () => { await send({ cmd: "dismissCapture" }); renderCapture(); };
  acts.append(save, skip);
  box.append(acts);
  captureEl.append(box);
}

async function refresh() {
  const st = await send({ cmd: "status" });
  bodyEl.innerHTML = "";
  if (!st.ok) {
    statusEl.textContent = "agent offline";
    statusEl.className = "status locked";
    bodyEl.append(el("div", { className: "muted", textContent: st.error || "Could not reach the Maliketh agent. Open the desktop app." }));
    return;
  }
  if (st.vault_exists === false) {
    statusEl.textContent = "no vault";
    statusEl.className = "status locked";
    bodyEl.append(el("div", { className: "muted", textContent: "No vault yet. Create one in the Maliketh desktop app." }));
    return;
  }
  if (st.locked) {
    statusEl.textContent = "locked";
    statusEl.className = "status locked";
    if (st.allow_browser_unlock) {
      const pw = el("input", { type: "password", placeholder: "Master password" });
      pw.setAttribute(
        "style",
        "width:100%;box-sizing:border-box;background:#0f0d15;color:#eee;border:1px solid #2a2735;border-radius:6px;padding:7px;margin-bottom:8px"
      );
      const btn = el("button", { textContent: "Unlock" });
      btn.style.width = "100%";
      const err = el("div", { className: "muted", textContent: "", style: "margin-top:6px;color:#f08c00" });
      const submit = async () => {
        if (!pw.value) return;
        btn.disabled = true;
        const r = await send({ cmd: "unlock", password: pw.value });
        pw.value = "";
        if (r.ok) {
          renderCapture();
          refresh();
        } else {
          btn.disabled = false;
          err.textContent = r.error || "unlock failed";
          pw.focus();
        }
      };
      btn.onclick = submit;
      pw.addEventListener("keydown", (e) => {
        if (e.key === "Enter") submit();
      });
      bodyEl.append(pw, btn, err);
      pw.focus();
    } else {
      bodyEl.append(
        el("div", {
          className: "muted",
          textContent:
            "Vault is locked. Unlock it from the Maliketh desktop app — or enable browser unlock in the app's Settings.",
        })
      );
    }
    return;
  }
  statusEl.textContent = "unlocked";
  statusEl.className = "status unlocked";
  const m = await send({ cmd: "matchActive" });
  const entries = (m.ok && m.entries) || [];
  if (!entries.length) {
    bodyEl.append(el("div", { className: "muted", textContent: "No saved logins for this site." }));
    return;
  }
  for (const entry of entries) {
    const left = el("div", {},
      el("div", { className: "title", textContent: entry.title || entry.username || "(entry)" }),
      el("div", { className: "user", textContent: entry.username || "" })
    );
    const fill = el("button", { textContent: "Fill" });
    fill.onclick = async () => {
      fill.disabled = true;
      const r = await send({ cmd: "fillActive", entryId: entry.id });
      if (!r.ok) alert(r.error || "fill failed");
      window.close();
    };
    bodyEl.append(el("div", { className: "row" }, left, fill));
  }
}

document.getElementById("help").onclick = () => {
  chrome.tabs.create({ url: chrome.runtime.getURL("welcome.html") });
  window.close();
};

document.getElementById("lock").onclick = async () => {
  await send({ cmd: "lock" });
  refresh();
};

document.getElementById("gen").onclick = async () => {
  const out = document.getElementById("genout");
  const r = await send({ cmd: "generate", length: 20 });
  if (r.ok) {
    out.style.display = "block";
    document.getElementById("genfield").value = r.password;
  } else {
    alert(r.error || "generate failed (vault locked?)");
  }
};

document.getElementById("gencopy").onclick = async () => {
  const f = document.getElementById("genfield");
  try { await navigator.clipboard.writeText(f.value); } catch (e) {}
};

renderCapture();
refresh();
