(async function () {
  "use strict";
  const res = await fetch("/officer/api/analytics");
  const d = await res.json();
  const palette = ["#0b3a5b", "#0f766e", "#b45309", "#7c3aed", "#be123c", "#2563eb", "#4d7c0f", "#a16207", "#475569", "#0e7490"];
  const grid = { color: "rgba(128,140,155,.25)" };

  document.getElementById("total-loss").textContent = "₹" + d.total_loss.toLocaleString("en-IN");

  new Chart(document.getElementById("c-daily"), {
    type: "line",
    data: { labels: d.daily.labels.map((x) => x.slice(5)), datasets: [{ label: "Complaints", data: d.daily.values, borderColor: palette[0], backgroundColor: palette[0], tension: 0.25 }] },
    options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 }, grid }, x: { grid } } },
  });
  new Chart(document.getElementById("c-cat"), {
    type: "bar",
    data: { labels: Object.keys(d.categories), datasets: [{ data: Object.values(d.categories), backgroundColor: palette[1] }] },
    options: { indexAxis: "y", maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 }, grid }, y: { grid } } },
  });
  new Chart(document.getElementById("c-status"), {
    type: "doughnut",
    data: { labels: Object.keys(d.statuses), datasets: [{ data: Object.values(d.statuses), backgroundColor: palette.slice(0, 5) }] },
    options: { maintainAspectRatio: false, plugins: { legend: { position: "bottom" } } },
  });

  const tb = document.getElementById("repeat-body");
  if (!d.repeat_identifiers.length) {
    tb.innerHTML = '<tr><td colspan="3" class="muted">No identifier has been reported more than once yet.</td></tr>';
  }
  d.repeat_identifiers.forEach((r) => {
    const tr = document.createElement("tr");
    [r.kind, r.value, r.complaints].forEach((v, i) => {
      const td = document.createElement("td");
      td.textContent = v;
      if (i === 1) td.className = "mono";
      tr.appendChild(td);
    });
    tb.appendChild(tr);
  });
})();
