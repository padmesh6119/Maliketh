// content script — login detection + proactive fill/save prompts
(() => {
  if (window.__malikethInjected) return;
  window.__malikethInjected = true;

  const PW = 'input[type="password"]';
  const USER_TYPES = ["text", "email", "tel", ""];
  let saveSig = "";
  let fillOfferedFor = "";
  let bannerHost = null;
  let picker = null;

  function send(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (resp) => {
          if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
          else resolve(resp || { ok: false });
        });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      }
    });
  }

  function visible(el) {
    if (!el) return false;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return false;
    const s = getComputedStyle(el);
    return s.visibility !== "hidden" && s.display !== "none";
  }

  function passwordFields() {
    return Array.from(document.querySelectorAll(PW)).filter(visible);
  }

  function usernameFor(pwField) {
    const scope = pwField.form || document;
    const inputs = Array.from(scope.querySelectorAll("input")).filter(
      (i) => i !== pwField && visible(i) && USER_TYPES.includes((i.getAttribute("type") || "").toLowerCase())
    );
    let preceding = null;
    for (const c of inputs) {
      if (pwField.compareDocumentPosition(c) & Node.DOCUMENT_POSITION_PRECEDING) preceding = c;
    }
    return preceding || inputs[inputs.length - 1] || null;
  }

  function setValue(input, value) {
    if (!input) return;
    const setter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value");
    if (setter && setter.set) setter.set.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function applyFill(username, password) {
    const fields = passwordFields();
    if (!fields.length) return false;
    const pw = fields[0];
    const user = usernameFor(pw);
    if (user && username) setValue(user, username);
    setValue(pw, password);
    return true;
  }

  function mk(tag, css, text) {
    const e = document.createElement(tag);
    if (css) e.style.cssText = css;
    if (text != null) e.textContent = text;
    return e;
  }

  function closeBanner() {
    if (bannerHost) {
      bannerHost.remove();
      bannerHost = null;
    }
  }

  function showBanner(title, sub, buttons) {
    closeBanner();
    const host = mk("div", "all:initial;position:fixed;top:14px;right:14px;z-index:2147483647");
    const root = host.attachShadow({ mode: "closed" });
    const card = mk(
      "div",
      "font:13px/1.4 system-ui,sans-serif;background:#15131c;color:#eee;border:1px solid #b5179e;border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.5);width:288px;overflow:hidden"
    );
    card.appendChild(mk("div", "padding:11px 13px 4px;font-weight:700;color:#b5179e", title));
    card.appendChild(mk("div", "padding:0 13px 11px;color:#cfc8dc;font-size:12px;word-break:break-word", sub));
    const row = mk("div", "display:flex;gap:8px;padding:0 13px 13px");
    buttons.forEach((b) => {
      const btn = mk(
        "button",
        "flex:1;font:inherit;border:none;border-radius:7px;padding:7px 10px;cursor:pointer;" +
          (b.primary ? "background:#b5179e;color:#fff" : "background:#241f30;color:#cfc8dc"),
        b.label
      );
      btn.onclick = () => {
        closeBanner();
        Promise.resolve().then(b.onClick);
      };
      row.appendChild(btn);
    });
    card.appendChild(row);
    root.appendChild(card);
    document.documentElement.appendChild(host);
    bannerHost = host;
  }

  function closePicker() {
    if (picker) picker.remove();
    picker = null;
    document.removeEventListener("click", onOutside, true);
  }

  function onOutside(e) {
    if (picker && !picker.contains(e.target)) closePicker();
  }

  function openPicker(anchor, entries) {
    closePicker();
    const host = mk("div", "all:initial;position:absolute;z-index:2147483647");
    const root = host.attachShadow({ mode: "closed" });
    const box = mk(
      "div",
      "font:13px/1.4 system-ui,sans-serif;background:#15131c;color:#eee;border:1px solid #b5179e;border-radius:10px;box-shadow:0 8px 28px rgba(0,0,0,.45);min-width:220px;overflow:hidden"
    );
    box.appendChild(mk("div", "padding:7px 11px;font-weight:600;color:#b5179e;border-bottom:1px solid #2a2735", "Maliketh"));
    entries.forEach((entry) => {
      const r = mk("div", "padding:8px 11px;cursor:pointer");
      r.onmouseenter = () => (r.style.background = "#241f30");
      r.onmouseleave = () => (r.style.background = "transparent");
      r.appendChild(mk("div", "font-weight:600", entry.title || entry.username || "(entry)"));
      if (entry.username) r.appendChild(mk("div", "font-size:11px;color:#9a93a8", entry.username));
      r.addEventListener("click", () => {
        doFill(entry);
        closePicker();
      });
      box.appendChild(r);
    });
    root.appendChild(box);
    document.documentElement.appendChild(host);
    const rect = anchor.getBoundingClientRect();
    host.style.left = window.scrollX + rect.left + "px";
    host.style.top = window.scrollY + rect.bottom + 4 + "px";
    picker = host;
    setTimeout(() => document.addEventListener("click", onOutside, true), 0);
  }

  async function doFill(entry) {
    const r = await send({ cmd: "fill", entryId: entry.id });
    if (r.ok && r.entry) applyFill(r.entry.username, r.entry.password);
    else if (r.locked) showBanner("Maliketh is locked", "Open the Maliketh icon to unlock, then fill.", [{ label: "OK", primary: true, onClick: () => {} }]);
  }

  function isLoginField(t) {
    if (!t || !t.matches) return false;
    if (t.matches(PW)) return true;
    if (!USER_TYPES.includes((t.getAttribute("type") || "").toLowerCase())) return false;
    return passwordFields().some((p) => usernameFor(p) === t);
  }

  async function maybeOfferFill() {
    if (!passwordFields().length) return;
    const origin = location.origin;
    if (fillOfferedFor === origin) return;
    const resp = await send({ cmd: "match" });
    if (resp.ok && Array.isArray(resp.entries) && resp.entries.length) {
      fillOfferedFor = origin;
      const entries = resp.entries;
      const sub =
        entries.length === 1
          ? "Fill saved login " + (entries[0].username || entries[0].title || "") + "?"
          : entries.length + " saved logins for this site — pick one to fill.";
      showBanner("Maliketh", sub, [
        {
          label: "Fill",
          primary: true,
          onClick: () => (entries.length === 1 ? doFill(entries[0]) : openPicker(passwordFields()[0], entries)),
        },
        { label: "Dismiss", onClick: () => {} },
      ]);
    } else if (resp.locked && fillOfferedFor !== origin + "#locked") {
      fillOfferedFor = origin + "#locked";
      showBanner("Maliketh is locked", "Open the Maliketh icon to unlock, then return to fill.", [
        { label: "OK", primary: true, onClick: () => {} },
      ]);
    }
  }

  function offerSave() {
    for (const pw of passwordFields()) {
      if (!pw.value) continue;
      const user = usernameFor(pw);
      const username = user ? user.value : "";
      const password = pw.value;
      const sig = username + "\x00" + password;
      if (sig === saveSig) return;
      saveSig = sig;
      send({ cmd: "match" }).then((resp) => {
        const existing = !!(resp.ok && (resp.entries || []).some((e) => e.username === username));
        const verb = existing ? "Update" : "Save";
        showBanner(
          "Maliketh — " + verb.toLowerCase() + " this login?",
          (username || "(no username)") + " @ " + location.host,
          [
            {
              label: verb,
              primary: true,
              onClick: async () => {
                const r = await send({ cmd: "capture", username, password });
                if (!r.ok && r.locked)
                  showBanner("Maliketh is locked", "Unlock from the Maliketh icon, then try saving again.", [
                    { label: "OK", primary: true, onClick: () => {} },
                  ]);
              },
            },
            { label: "Not now", onClick: () => {} },
          ]
        );
      });
      return;
    }
  }

  document.addEventListener(
    "focusin",
    (e) => {
      if (isLoginField(e.target) && passwordFields().length) maybeOfferFill();
    },
    true
  );
  document.addEventListener("submit", offerSave, true);
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key === "Enter" && e.target && e.target.matches && e.target.matches(PW)) offerSave();
    },
    true
  );
  document.addEventListener(
    "click",
    (e) => {
      const el = e.target && e.target.closest ? e.target.closest('button,[type="submit"],[role="button"]') : null;
      if (el && /log\s?in|sign\s?in|continue|submit|next/i.test(el.textContent || el.value || "")) setTimeout(offerSave, 0);
    },
    true
  );

  let mutTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(mutTimer);
    mutTimer = setTimeout(maybeOfferFill, 800);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(maybeOfferFill, 600);

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg && msg.cmd === "fillFields") sendResponse({ ok: applyFill(msg.username, msg.password) });
    return false;
  });
})();
