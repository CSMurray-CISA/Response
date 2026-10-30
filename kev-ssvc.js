"use strict";

const state = {
  metadata: null,
  rows: [],
  filtered: [],
  sortKey: "dateAdded",
  sortDirection: "desc",
  page: 1,
  pageSize: 100
};

const elements = {
  datasetState: document.getElementById("datasetState"),
  catalogStat: document.getElementById("catalogStat"),
  filteredStat: document.getElementById("filteredStat"),
  impactStat: document.getElementById("impactStat"),
  automatableStat: document.getElementById("automatableStat"),
  search: document.getElementById("searchFilter"),
  from: document.getElementById("dateFrom"),
  to: document.getElementById("dateTo"),
  impact: document.getElementById("impactFilter"),
  automatable: document.getElementById("automatableFilter"),
  exploitation: document.getElementById("exploitationFilter"),
  vendor: document.getElementById("vendorFilter"),
  product: document.getElementById("productFilter"),
  reset: document.getElementById("resetFilters"),
  export: document.getElementById("exportCsv"),
  rows: document.getElementById("kevRows"),
  resultSummary: document.getElementById("resultSummary"),
  pageSize: document.getElementById("pageSize"),
  previous: document.getElementById("previousPage"),
  next: document.getElementById("nextPage"),
  pageStatus: document.getElementById("pageStatus"),
  dialog: document.getElementById("kevDetail"),
  detail: document.getElementById("detailContent"),
  detailClose: document.getElementById("detailClose"),
  loadError: document.getElementById("loadError")
};

const escapeHtml = value => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

function titleCase(value) {
  const text = String(value || "unknown");
  if (text === "poc") return "PoC";
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function badge(value) {
  const normalized = String(value || "unknown").toLowerCase();
  return `<span class="ssvc-badge ssvc-${escapeHtml(normalized)}">${escapeHtml(titleCase(normalized))}</span>`;
}

function formatDateTime(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function setOptions(select, values, label) {
  const current = select.value;
  select.innerHTML = `<option value="">${escapeHtml(label)}</option>` + values
    .map(value => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`)
    .join("");
  if (values.includes(current)) select.value = current;
}

function populateVendors() {
  const vendors = [...new Set(state.rows.map(row => row.vendor).filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  setOptions(elements.vendor, vendors, "All vendors");
  populateProducts();
}

function populateProducts() {
  const vendor = elements.vendor.value;
  const products = [...new Set(state.rows
    .filter(row => !vendor || row.vendor === vendor)
    .map(row => row.product)
    .filter(Boolean))]
    .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: "base" }));
  setOptions(elements.product, products, "All products");
}

function searchable(row) {
  return [row.cve, row.vendor, row.product, row.vulnerabilityName, ...(row.cwes || [])]
    .join(" ")
    .toLowerCase();
}

function sortValue(row, key) {
  if (key === "cwes") return (row.cwes || []).join(", ");
  if (key === "cvss") return Number(row.cvss?.score ?? -1);
  return row[key] ?? "";
}

function applyFilters() {
  const query = elements.search.value.trim().toLowerCase();
  const from = elements.from.value;
  const to = elements.to.value;
  const impact = elements.impact.value;
  const automatable = elements.automatable.value;
  const exploitation = elements.exploitation.value;
  const vendor = elements.vendor.value;
  const product = elements.product.value;

  state.filtered = state.rows.filter(row => {
    if (query && !searchable(row).includes(query)) return false;
    if (from && row.dateAdded < from) return false;
    if (to && row.dateAdded > to) return false;
    if (impact && row.technicalImpact !== impact) return false;
    if (automatable && row.automatable !== automatable) return false;
    if (exploitation && row.exploitation !== exploitation) return false;
    if (vendor && row.vendor !== vendor) return false;
    if (product && row.product !== product) return false;
    return true;
  });

  const direction = state.sortDirection === "asc" ? 1 : -1;
  state.filtered.sort((left, right) => {
    const a = sortValue(left, state.sortKey);
    const b = sortValue(right, state.sortKey);
    if (typeof a === "number" && typeof b === "number") return (a - b) * direction;
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" }) * direction;
  });

  const pageCount = getPageCount();
  if (state.page > pageCount) state.page = Math.max(1, pageCount);
  render();
}

function getPageCount() {
  if (state.pageSize === Infinity) return 1;
  return Math.max(1, Math.ceil(state.filtered.length / state.pageSize));
}

function visibleRows() {
  if (state.pageSize === Infinity) return state.filtered;
  const start = (state.page - 1) * state.pageSize;
  return state.filtered.slice(start, start + state.pageSize);
}

function cvssHtml(row) {
  if (!row.cvss?.score && row.cvss?.score !== 0) return "—";
  const score = Number(row.cvss.score).toFixed(1);
  return `<span class="cvss-score">${score}<small>v${escapeHtml(row.cvss.version || "?")}</small></span>`;
}

function renderRows() {
  const rows = visibleRows();
  if (!rows.length) {
    elements.rows.innerHTML = '<tr><td colspan="11" class="empty-cell">No KEV entries match these filters.</td></tr>';
    return;
  }

  elements.rows.innerHTML = rows.map(row => `
    <tr data-cve="${escapeHtml(row.cve)}" tabindex="0" aria-label="Open details for ${escapeHtml(row.cve)}">
      <td><span class="cve-cell">${escapeHtml(row.cve)}</span></td>
      <td>${escapeHtml(row.vendor || "—")}</td>
      <td>${escapeHtml(row.product || "—")}</td>
      <td><span class="cwe-cell">${escapeHtml((row.cwes || []).join(", ") || "—")}</span></td>
      <td>${cvssHtml(row)}</td>
      <td>${escapeHtml(row.vulnerabilityName || "—")}</td>
      <td>${badge(row.exploitation)}</td>
      <td>${badge(row.technicalImpact)}</td>
      <td>${badge(row.automatable)}</td>
      <td class="date-cell">${escapeHtml(row.dateAdded || "—")}</td>
      <td class="date-cell">${escapeHtml(row.dueDate || "—")}</td>
    </tr>`).join("");
}

function renderStats() {
  elements.catalogStat.textContent = state.rows.length.toLocaleString();
  elements.filteredStat.textContent = state.filtered.length.toLocaleString();
  elements.impactStat.textContent = state.filtered.filter(row => row.technicalImpact === "total").length.toLocaleString();
  elements.automatableStat.textContent = state.filtered.filter(row => row.automatable === "yes").length.toLocaleString();
}

function renderPagination() {
  const count = state.filtered.length;
  const pageCount = getPageCount();
  const start = count ? (state.pageSize === Infinity ? 1 : (state.page - 1) * state.pageSize + 1) : 0;
  const end = state.pageSize === Infinity ? count : Math.min(state.page * state.pageSize, count);
  elements.resultSummary.textContent = `${count.toLocaleString()} entries · showing ${start.toLocaleString()}–${end.toLocaleString()}`;
  elements.pageStatus.textContent = `Page ${state.page.toLocaleString()} of ${pageCount.toLocaleString()}`;
  elements.previous.disabled = state.page <= 1;
  elements.next.disabled = state.page >= pageCount;
}

function renderSortButtons() {
  document.querySelectorAll("[data-sort]").forEach(button => {
    const active = button.dataset.sort === state.sortKey;
    button.classList.toggle("active", active);
    button.querySelector("span").textContent = active ? (state.sortDirection === "asc" ? "↑" : "↓") : "↕";
  });
}

function render() {
  renderStats();
  renderRows();
  renderPagination();
  renderSortButtons();
}

function resetFilters() {
  [elements.search, elements.from, elements.to, elements.impact, elements.automatable, elements.exploitation, elements.vendor]
    .forEach(element => { element.value = ""; });
  populateProducts();
  elements.product.value = "";
  state.page = 1;
  state.sortKey = "dateAdded";
  state.sortDirection = "desc";
  applyFilters();
}

function csvCell(value) {
  const text = String(value ?? "");
  return `"${text.replaceAll('"', '""')}"`;
}

function exportCsv() {
  const headers = ["CVE", "Vendor", "Product", "CWE", "CVSS", "CVSS Version", "Vulnerability Name", "Exploitation State", "Technical Impact", "Automatable", "KEV Added Date", "KEV Due Date"];
  const lines = [headers.map(csvCell).join(",")];
  state.filtered.forEach(row => lines.push([
    row.cve, row.vendor, row.product, (row.cwes || []).join("; "), row.cvss?.score ?? "", row.cvss?.version ?? "",
    row.vulnerabilityName, row.exploitation, row.technicalImpact, row.automatable, row.dateAdded, row.dueDate
  ].map(csvCell).join(",")));
  const blob = new Blob(["\ufeff" + lines.join("\r\n")], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `kev-with-ssvc-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function vulnrichmentUrl(cve) {
  const match = /^CVE-(\d{4})-(\d+)$/i.exec(cve);
  if (!match) return "https://github.com/cisagov/vulnrichment";
  const bucket = `${Math.floor(Number(match[2]) / 1000)}xxx`;
  return `https://github.com/cisagov/vulnrichment/blob/develop/${match[1]}/${bucket}/${cve}.json`;
}

function openDetails(cve) {
  const row = state.rows.find(item => item.cve === cve);
  if (!row) return;
  elements.detail.innerHTML = `
    <p class="kev-eyebrow">Known exploited vulnerability</p>
    <h2>${escapeHtml(row.cve)}</h2>
    <p class="detail-name">${escapeHtml(row.vulnerabilityName || "Unnamed vulnerability")}</p>
    <dl class="detail-grid">
      <dt>Vendor / product</dt><dd>${escapeHtml(row.vendor)} / ${escapeHtml(row.product)}</dd>
      <dt>CWE</dt><dd>${escapeHtml((row.cwes || []).join(", ") || "Unknown")} ${row.cweSource ? `· ${escapeHtml(row.cweSource)}` : ""}</dd>
      <dt>CVSS</dt><dd>${row.cvss?.score ?? "Unknown"}${row.cvss?.version ? ` (v${escapeHtml(row.cvss.version)})` : ""}${row.cvssSource ? ` · ${escapeHtml(row.cvssSource)}` : ""}</dd>
      <dt>SSVC</dt><dd>${badge(row.exploitation)} ${badge(row.technicalImpact)} ${badge(row.automatable)}</dd>
      <dt>SSVC source</dt><dd>${escapeHtml(row.ssvcSource || "Unknown")}${row.ssvcVersion ? ` · version ${escapeHtml(row.ssvcVersion)}` : ""}</dd>
      <dt>KEV dates</dt><dd>Added ${escapeHtml(row.dateAdded || "Unknown")} · due ${escapeHtml(row.dueDate || "Unknown")}</dd>
      <dt>Ransomware use</dt><dd>${escapeHtml(row.knownRansomwareCampaignUse || "Unknown")}</dd>
    </dl>
    <section class="detail-section"><h3>Description</h3><p>${escapeHtml(row.shortDescription || "No description provided.")}</p></section>
    <section class="detail-section"><h3>Required action</h3><p>${escapeHtml(row.requiredAction || "No required action provided.")}</p></section>
    ${row.notes ? `<section class="detail-section"><h3>Notes</h3><p>${escapeHtml(row.notes)}</p></section>` : ""}
    <section class="detail-section"><h3>Sources</h3><div class="detail-links">
      <a href="https://github.com/cisagov/kev-data" target="_blank" rel="noopener">KEV data ↗</a>
      <a href="${escapeHtml(vulnrichmentUrl(row.cve))}" target="_blank" rel="noopener">Vulnrichment record ↗</a>
      <a href="https://www.cve.org/CVERecord?id=${encodeURIComponent(row.cve)}" target="_blank" rel="noopener">CVE.org ↗</a>
    </div></section>`;
  elements.dialog.showModal();
}

function bindEvents() {
  [elements.search, elements.from, elements.to, elements.impact, elements.automatable, elements.exploitation, elements.product]
    .forEach(element => element.addEventListener(element === elements.search ? "input" : "change", () => {
      state.page = 1;
      applyFilters();
    }));

  elements.vendor.addEventListener("change", () => {
    populateProducts();
    state.page = 1;
    applyFilters();
  });
  elements.reset.addEventListener("click", resetFilters);
  elements.export.addEventListener("click", exportCsv);
  elements.pageSize.addEventListener("change", () => {
    state.pageSize = elements.pageSize.value === "all" ? Infinity : Number(elements.pageSize.value);
    state.page = 1;
    render();
  });
  elements.previous.addEventListener("click", () => { if (state.page > 1) { state.page -= 1; render(); } });
  elements.next.addEventListener("click", () => { if (state.page < getPageCount()) { state.page += 1; render(); } });
  document.querySelectorAll("[data-sort]").forEach(button => button.addEventListener("click", () => {
    const key = button.dataset.sort;
    if (state.sortKey === key) state.sortDirection = state.sortDirection === "asc" ? "desc" : "asc";
    else { state.sortKey = key; state.sortDirection = "asc"; }
    state.page = 1;
    applyFilters();
  }));
  elements.rows.addEventListener("click", event => {
    const row = event.target.closest("tr[data-cve]");
    if (row) openDetails(row.dataset.cve);
  });
  elements.rows.addEventListener("keydown", event => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const row = event.target.closest("tr[data-cve]");
    if (row) { event.preventDefault(); openDetails(row.dataset.cve); }
  });
  elements.detailClose.addEventListener("click", () => elements.dialog.close());
  elements.dialog.addEventListener("click", event => { if (event.target === elements.dialog) elements.dialog.close(); });
}

async function loadData() {
  try {
    const response = await fetch("data/kev-ssvc.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`Staged dataset returned HTTP ${response.status}`);
    const payload = await response.json();
    if (!Array.isArray(payload.vulnerabilities)) throw new Error("Staged dataset is missing its vulnerability list");
    state.metadata = payload;
    state.rows = payload.vulnerabilities;
    populateVendors();
    applyFilters();
    elements.datasetState.innerHTML = `<span class="dataset-dot"></span><div><strong>${payload.count.toLocaleString()} KEV entries staged</strong><small>Updated ${escapeHtml(formatDateTime(payload.generatedAt))}</small></div>`;
  } catch (error) {
    elements.datasetState.innerHTML = '<span class="dataset-dot error"></span><div><strong>Dataset unavailable</strong><small>Refresh after the next scheduled update</small></div>';
    elements.rows.innerHTML = '<tr><td colspan="11" class="empty-cell">The staged KEV dataset could not be loaded.</td></tr>';
    elements.loadError.textContent = `KEV with SSVC could not open its staged data: ${error.message}`;
    elements.loadError.classList.remove("hidden");
  }
}

bindEvents();
loadData();
