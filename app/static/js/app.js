// CyberGuard front-end: browser-side SHA-256 of evidence, dynamic identifier rows, integrity verification.
(function () {
  "use strict";
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

  async function sha256(file) {
    const buf = await file.arrayBuffer();
    const hash = await crypto.subtle.digest("SHA-256", buf);
    return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  // 1) Hash each chosen file in the browser BEFORE upload; the server recomputes and compares (transit integrity).
  document.querySelectorAll("input[data-hash-files]").forEach((input) => {
    const form = input.form;
    const out = form.querySelector("[data-hash-output]");
    const hidden = form.querySelector('input[name="client_hashes"]');
    input.addEventListener("change", async () => {
      const map = {};
      out.textContent = "";
      if (!window.crypto?.subtle) { out.textContent = "Browser hashing unavailable (needs HTTPS or localhost)."; return; }
      for (const f of input.files) {
        map[f.name] = await sha256(f);
        const p = document.createElement("p");
        p.className = "filehash mono";
        p.textContent = `${f.name} — SHA-256: ${map[f.name]}`;
        out.appendChild(p);
      }
      hidden.value = JSON.stringify(map);
    });
  });

  // 2) Add/remove suspect-identifier rows.
  const rows = document.getElementById("id-rows");
  const tpl = document.getElementById("id-row-tpl");
  if (rows && tpl) {
    const add = () => rows.appendChild(tpl.content.cloneNode(true));
    document.getElementById("add-id")?.addEventListener("click", add);
    rows.addEventListener("click", (e) => {
      if (e.target.matches("[data-remove-id]")) e.target.closest(".id-row").remove();
    });
    if (!rows.children.length) add();
    const hints = { upi: "name@bank", phone: "10-digit mobile", bank_account: "9–18 digits", email: "name@example.com", url: "example.com" };
    rows.addEventListener("change", (e) => {
      if (e.target.matches("select[name=id_kind]")) {
        e.target.closest(".id-row").querySelector("input").placeholder = hints[e.target.value] || "";
      }
    });
  }

  // 3) Integrity verification buttons (decrypt → re-hash → compare with DB and audit-log anchor).
  document.querySelectorAll("button[data-verify]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const out = btn.parentElement.querySelector(".verify-out");
      out.textContent = "Verifying…";
      try {
        const r = await fetch(btn.dataset.verify, { method: "POST", headers: { "X-CSRFToken": csrf } });
        const d = await r.json();
        out.className = "verify-out";
        if (d.ok) {
          out.innerHTML = '<span class="badge ok">✔ Intact</span> matches database and audit-log record';
        } else {
          const why = d.error || (!d.db_match ? "file differs from the recorded hash" : "audit-log anchor does not match");
          out.innerHTML = '<span class="badge bad">✖ Integrity check FAILED</span> ';
          out.appendChild(document.createTextNode(why));
        }
      } catch (e) {
        out.textContent = "Verification request failed.";
      }
    });
  });
})();
