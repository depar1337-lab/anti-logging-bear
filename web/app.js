// Anti-Logging Bear by Priest

const MB = 1024 * 1024;
const MAX_FILE_MB = 400;
const HISTORY_LIMIT = 20;
const SETTINGS_KEY = "alb.settings";
const HISTORY_KEY = "alb.history";
const RELEASES = "https://github.com/depar1337-lab/anti-logging-bear/releases/latest";

const DEFAULTS = { strict: false, maxUnpackedMb: 512, highContrast: false, largeText: false, keepHistory: true };

const POSE = { clean: "happy", suspicious: "worried", dangerous: "alarm" };
const BLURB = {
  clean: "Barry didn't spot anything suspicious. No scanner can promise a file is safe, so only run software from people you trust.",
  suspicious: "Something here is unusual. It might be harmless, but don't run it unless you trust where it came from.",
  dangerous: "This download shows clear signs of malware. Don't unzip or open it. Delete it, and don't move it to your computer.",
};
const SEVERITY_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

const $ = (id) => document.getElementById(id);
const views = { idle: $("view-idle"), scanning: $("view-scanning"), result: $("view-result"), downloads: $("view-downloads") };

let settings = load(SETTINGS_KEY, DEFAULTS);
let worker = null;
let engineReady = false;
let engineVersion = "";
let currentJob = null;
let lastResult = null;
let jobCounter = 0;
let currentView = "idle";
let viewBeforeDownloads = "idle";

function load(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? { ...fallback, ...JSON.parse(raw) } : { ...fallback };
  } catch {
    return { ...fallback };
  }
}

function loadList(key) {
  try {
    const value = JSON.parse(localStorage.getItem(key) || "[]");
    return Array.isArray(value) ? value : [];
  } catch {
    return [];
  }
}

function store(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* storage unavailable */ }
}

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else node.setAttribute(key, value);
  }
  node.append(...children.filter((child) => child !== null && child !== undefined));
  return node;
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < MB) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / MB).toFixed(1)} MB`;
}

function plural(count, word) {
  return `${count} ${word}${count === 1 ? "" : "s"}`;
}

// Engine

function startWorker() {
  engineReady = false;
  worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
  worker.onmessage = ({ data }) => handleWorker(data);
  worker.onerror = (event) => {
    event.preventDefault();
    engineFailed(event.message || "The scanner stopped unexpectedly.");
  };
  setEngineStatus(!settings.engineLoaded
    ? "Getting Barry ready. The first visit downloads about 14 MB, then it works offline."
    : "Getting Barry ready...");
}

function handleWorker(message) {
  switch (message.type) {
    case "ready":
      engineReady = true;
      engineVersion = message.version;
      if (!settings.engineLoaded) {
        settings.engineLoaded = true;
        store(SETTINGS_KEY, settings);
      }
      $("about-version").textContent = `Barry Bear ${engineVersion} (web)`;
      setEngineStatus("");
      if (currentJob) $("scan-step").textContent = "Reading the file...";
      break;
    case "fatal":
      engineFailed(message.message);
      break;
    case "progress":
      if (currentJob && message.id === currentJob.id) showProgress(message);
      break;
    case "result":
      if (currentJob && message.id === currentJob.id) finishScan(message.report);
      break;
    case "error":
      if (currentJob && message.id === currentJob.id) {
        console.error(message.message);
        scanFailed("Barry hit a problem reading this file. It may be damaged, or too big for your phone's memory.");
      }
      break;
  }
}

function engineFailed(detail) {
  console.error(detail);
  engineReady = false;
  setEngineStatus("Barry couldn't start. Check your connection and reload the page.", true);
  if (currentJob) scanFailed("Barry couldn't start, so this file wasn't checked.");
}

function setEngineStatus(text, isError = false) {
  const node = $("engine-status");
  node.textContent = text;
  node.classList.toggle("error", isError);
}

// Scanning

let progressFrame = 0;
let pendingProgress = null;

function showProgress(message) {
  pendingProgress = message;
  if (progressFrame) return;
  progressFrame = requestAnimationFrame(() => {
    progressFrame = 0;
    const { text, checked } = pendingProgress;
    $("scan-step").textContent = `${plural(checked, "file")} checked. ${text}`;
  });
}

async function scanFile(file) {
  if (!file) return;
  if (currentJob) cancelScan(false);
  if (file.size > MAX_FILE_MB * MB) {
    showError(file.name, `This file is ${formatSize(file.size)}. The web version checks files up to ${MAX_FILE_MB} MB. Use the Windows or Mac app for bigger downloads.`);
    return;
  }

  const job = { id: ++jobCounter, name: file.name, size: file.size };
  currentJob = job;
  $("scan-title").textContent = `Barry is checking ${file.name}`;
  $("scan-step").textContent = engineReady ? "Reading the file..." : "Getting Barry ready...";
  show("scanning", $("scan-title"));

  let buffer;
  try {
    buffer = await file.arrayBuffer();
  } catch {
    scanFailed("Barry couldn't read this file. If it's in iCloud, download it to your phone first.");
    return;
  }
  if (currentJob !== job) return;
  job.started = performance.now();
  worker.postMessage({
    type: "scan",
    id: job.id,
    name: file.name,
    buffer,
    options: { strict: settings.strict, maxUnpackedMb: settings.maxUnpackedMb },
  }, [buffer]);
}

function cancelScan(goIdle = true) {
  currentJob = null;
  worker.terminate();
  startWorker();
  if (goIdle) show("idle", $("choose-file"));
}

function finishScan(report) {
  currentJob = null;
  lastResult = report;
  renderResult(report);
  remember(report);
  show("result", $("verdict-title"));
}

function scanFailed(message) {
  const name = currentJob ? currentJob.name : "";
  currentJob = null;
  showError(name, message);
}

function showError(name, message) {
  lastResult = null;
  renderVerdict("suspicious", "Barry couldn't check this file", name);
  $("verdict-blurb").textContent = message;
  $("reasons").replaceChildren();
  $("save-report").hidden = true;
  $("toggle-details").hidden = true;
  setDetails(false);
  show("result", $("verdict-title"));
}

// Views

function show(name, focusTarget) {
  currentView = name;
  for (const [key, view] of Object.entries(views)) view.hidden = key !== name;
  if (name === "downloads") $("open-downloads").setAttribute("aria-current", "page");
  else $("open-downloads").removeAttribute("aria-current");
  if (name !== "downloads" && location.hash === "#downloads") history.replaceState(null, "", location.pathname + location.search);
  window.scrollTo({ top: 0 });
  if (focusTarget) focusTarget.focus({ preventScroll: true });
}

function renderVerdict(verdict, headline, meta) {
  const box = $("verdict");
  box.dataset.verdict = verdict;
  $("verdict-icon").setAttribute("href", `#v-${verdict}`);
  $("verdict-title").textContent = headline;
  $("verdict-meta").textContent = meta;
  const pose = POSE[verdict];
  const image = $("result-barry");
  image.src = `img/barry-${pose}.png`;
  image.srcset = `img/barry-${pose}@2x.png 2x`;
}

function renderResult(report) {
  const fileCount = Math.max(report.files.length - (report.files[0] && report.files[0].kind === "zip" ? 1 : 0), 1);
  const took = report.duration < 1 ? "under a second" : `${report.duration.toFixed(1)} seconds`;
  renderVerdict(report.verdict, report.headline, `${report.target} · ${plural(fileCount, "file")} checked in ${took}`);
  $("verdict-blurb").textContent = BLURB[report.verdict];
  $("save-report").hidden = false;
  $("toggle-details").hidden = false;

  $("reasons").replaceChildren(...report.reasons.map((reason) => el("li", {},
    el("span", { class: `sev ${reason.severity}`, text: SEVERITY_LABEL[reason.severity] }),
    el("span", { text: reason.text }))));

  const findings = report.findings;
  $("findings-count").textContent = findings.length || "";
  $("findings").replaceChildren(...(findings.length ? findings.map(renderFinding)
    : [el("li", { class: "muted", text: "Nothing to report." })]));

  $("files-count").textContent = report.files.length;
  $("files").replaceChildren(...report.files.map(renderFile));

  const addresses = report.indicators;
  $("addresses-card").hidden = addresses.length === 0;
  $("addresses-count").textContent = addresses.length || "";
  $("addresses").replaceChildren(...addresses.map((address) => el("li", { text: address })));

  $("engines").replaceChildren(...Object.entries(report.engines).map(([name, status]) =>
    el("li", {}, el("span", { text: name }), el("span", { text: status }))));

  setDetails(settings.showDetails === true);
}

function renderFinding(finding) {
  return el("li", {},
    el("div", { class: "finding-head" },
      el("span", { class: `sev ${finding.severity}`, text: SEVERITY_LABEL[finding.severity] }),
      el("span", { class: "finding-title", text: finding.title })),
    finding.path ? el("div", { class: "finding-path", text: finding.path }) : null,
    finding.detail ? el("p", { class: "finding-detail", text: finding.detail }) : null,
    ...finding.indicators.slice(0, 10).map((ioc) => el("div", { class: "ioc", text: ioc })));
}

function renderFile(file) {
  const lookup = el("a", {
    href: `https://www.virustotal.com/gui/file/${file.sha256}`,
    target: "_blank",
    rel: "noopener noreferrer",
    text: "VirusTotal",
  });
  const bazaar = el("a", {
    href: `https://bazaar.abuse.ch/browse.php?search=sha256%3A${file.sha256}`,
    target: "_blank",
    rel: "noopener noreferrer",
    text: "MalwareBazaar",
  });
  const copy = el("button", { type: "button", class: "link-button", text: "Copy SHA-256" });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(file.sha256);
      copy.textContent = "Copied";
    } catch {
      copy.textContent = "Couldn't copy";
    }
    setTimeout(() => { copy.textContent = "Copy SHA-256"; }, 1600);
  });
  return el("li", {},
    el("div", { class: "file-path", text: file.path }),
    el("div", { class: "file-meta", text: `${file.kind} · ${formatSize(file.size)}` }),
    el("code", { class: "hash", text: file.sha256 }),
    el("div", { class: "file-actions" }, lookup, bazaar, copy));
}

function setDetails(open) {
  $("details").hidden = !open;
  const toggle = $("toggle-details");
  toggle.setAttribute("aria-expanded", String(open));
  toggle.textContent = open ? "Hide details" : "Show details";
}

// Report

async function saveReport() {
  if (!lastResult) return;
  const base = lastResult.target.replace(/\.[^.]+$/, "") || "download";
  const file = new File([lastResult.html], `${base} - Barry report.html`, { type: "text/html" });
  const touch = matchMedia("(pointer: coarse)").matches;
  if (touch && navigator.canShare && navigator.canShare({ files: [file] })) {
    try {
      await navigator.share({ files: [file], title: "Barry Bear report" });
      return;
    } catch (error) {
      if (error && error.name === "AbortError") return;
    }
  }
  const url = URL.createObjectURL(file);
  const link = el("a", { href: url, download: file.name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// History

function remember(report) {
  if (!settings.keepHistory) return;
  const entry = {
    name: report.target,
    verdict: report.verdict,
    headline: report.headline,
    files: report.files.length,
    when: new Date().toISOString(),
  };
  store(HISTORY_KEY, [entry, ...loadList(HISTORY_KEY)].slice(0, HISTORY_LIMIT));
  renderHistory();
}

function renderHistory() {
  const items = settings.keepHistory ? loadList(HISTORY_KEY) : [];
  $("recent").hidden = items.length === 0;
  const formatter = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  $("recent-list").replaceChildren(...items.slice(0, 8).map((item) => {
    let when = "";
    try { when = formatter.format(new Date(item.when)); } catch { /* bad date */ }
    return el("li", {},
      el("span", { class: `dot ${item.verdict}`, "aria-hidden": "true" }),
      el("span", { class: "name", text: item.name }),
      el("span", { class: "meta", text: `${item.headline} · ${when}` }));
  }));
}

// Downloads

const UNSIGNED_WINDOWS = "The app isn't code-signed yet, so Windows may say it protected your PC. Choose More info, then Run anyway.";
const UNSIGNED_MAC = "The app isn't notarised yet, so the first time, right-click it and choose Open.";
const MAC_CHIP = "Not sure which Mac you have? Open Apple menu > About This Mac. If it lists a Chip, it's Apple silicon. If it lists a Processor, it's Intel.";

const BUILDS = {
  windows: { label: "Download for Windows", name: "Windows installer", detail: "Windows 7 to 11, 64-bit. Most PCs.", file: "BarryBear-x64-setup.exe" },
  windows32: { label: "Download for Windows (32-bit)", name: "Windows installer, 32-bit", detail: "Older 32-bit Windows 7 to 10.", file: "BarryBear-x86-setup.exe" },
  portable: { name: "Portable zip", detail: "No installer. Unzip and run, 64-bit.", file: "BarryBear-x64-portable.zip" },
  portable32: { name: "Portable zip, 32-bit", detail: "No installer, for 32-bit Windows.", file: "BarryBear-x86-portable.zip" },
  macArm: { label: "Download for Mac", short: "Mac with Apple silicon", name: "Mac with Apple silicon", detail: "M1 or later, macOS 11 or newer.", file: "BarryBear-macOS-AppleSilicon.dmg" },
  macIntel: { label: "Download for Intel Mac", short: "Intel Mac", name: "Intel Mac", detail: "macOS 10.15 or newer.", file: "BarryBear-macOS-Intel.dmg" },
};

const GROUPS = [
  { title: "Windows", builds: ["windows", "windows32", "portable", "portable32"], note: UNSIGNED_WINDOWS },
  { title: "Mac", builds: ["macArm", "macIntel"], note: `${MAC_CHIP} ${UNSIGNED_MAC}` },
];

let recommended = null;

function desktopPlatform() {
  const agent = navigator.userAgent;
  const platform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
  if (/Android|iPhone|iPad|iPod/i.test(agent)) return null;
  if (/Win/i.test(platform) || /Windows NT/.test(agent)) {
    return /Win64|WOW64|x64|amd64|arm64/i.test(agent) || navigator.userAgentData ? "windows" : "windows32";
  }
  if (/Mac/i.test(platform) && navigator.maxTouchPoints < 2) return "mac";
  return null;
}

async function macArchitecture() {
  try {
    const hints = await navigator.userAgentData.getHighEntropyValues(["architecture"]);
    if (hints.architecture === "x86") return "intel";
    if (hints.architecture === "arm") return "arm";
  } catch { /* Safari and Firefox don't say */ }
  return "unknown";
}

const downloadUrl = (build) => `${RELEASES}/download/${build.file}`;

async function offerDesktopApp() {
  const platform = desktopPlatform();
  if (!platform) return;
  let note = `Windows 7 to 11. ${UNSIGNED_WINDOWS}`;
  recommended = platform;
  if (platform === "mac") {
    const arch = await macArchitecture();
    recommended = arch === "intel" ? "macIntel" : "macArm";
    const other = arch === "intel" ? BUILDS.macArm : BUILDS.macIntel;
    const alternate = $("desktop-alternate");
    alternate.href = downloadUrl(other);
    alternate.textContent = other.short;
    alternate.hidden = false;
    note = arch === "unknown"
      ? `Needs macOS 11 or later (10.15 on Intel). ${MAC_CHIP} ${UNSIGNED_MAC}`
      : `Needs macOS ${arch === "intel" ? "10.15" : "11"} or later. ${UNSIGNED_MAC}`;
  }
  const main = BUILDS[recommended];
  $("desktop-download").href = downloadUrl(main);
  $("desktop-download-label").textContent = main.label;
  $("desktop-note").textContent = note;
  $("desktop-app").hidden = false;
  renderDownloads();
}

function renderDownloads() {
  $("downloads-releases").href = RELEASES.replace(/\/latest$/, "");
  $("download-groups").replaceChildren(...GROUPS.map((group) => el("fieldset", { class: "group" },
    el("legend", { text: group.title }),
    el("ul", { class: "download-list" }, ...group.builds.map((key) => {
      const build = BUILDS[key];
      const best = key === recommended;
      return el("li", { class: best ? "recommended" : "" },
        el("span", { class: "name" }, build.name, best ? el("span", { class: "tag", text: "This device" }) : null),
        el("span", { class: "detail", text: build.detail }),
        el("a", { class: `button small${best ? " primary" : ""}`, href: downloadUrl(build), "aria-label": `Download ${build.name}` },
          el("span", { text: "Download" })));
    })),
    el("p", { class: "note", text: group.note }))));
}

function route() {
  if (location.hash === "#downloads") {
    if (currentView !== "downloads") viewBeforeDownloads = currentView;
    show("downloads", $("downloads-title"));
  } else if (currentView === "downloads") {
    const back = viewBeforeDownloads === "scanning" && !currentJob ? "idle" : viewBeforeDownloads;
    show(back, back === "idle" ? $("choose-file") : null);
  }
}

function bindDownloads() {
  let pushed = false;
  const open = () => {
    if (location.hash === "#downloads") return;
    pushed = true;
    location.hash = "downloads";
  };
  $("open-downloads").addEventListener("click", open);
  $("desktop-all").addEventListener("click", open);
  $("about-downloads").addEventListener("click", (event) => {
    event.preventDefault();
    $("settings").close();
    open();
  });
  $("downloads-back").addEventListener("click", () => {
    if (pushed) {
      pushed = false;
      history.back();
    } else {
      history.replaceState(null, "", location.pathname + location.search);
      route();
    }
  });
  window.addEventListener("hashchange", route);
  renderDownloads();
  route();
}

// Barry's tummy

const TUMMY = { x: 200 / 420, y: 362 / 460, rx: 64 / 420, ry: 68 / 460 };

function onTummy(event, image) {
  const box = image.getBoundingClientRect();
  const x = ((event.clientX - box.left) / box.width - TUMMY.x) / TUMMY.rx;
  const y = ((event.clientY - box.top) / box.height - TUMMY.y) / TUMMY.ry;
  return x * x + y * y <= 1;
}

function bindTummy() {
  const mood = (image, pose) => {
    image.dataset.pose = pose;
    image.src = `img/barry-${pose}.png`;
    image.srcset = `img/barry-${pose}@2x.png 2x`;
  };
  const settle = (image) => {
    image.classList.remove("queasy", "poked");
    if (!image.dataset.pose) return;
    image.src = image.dataset.src;
    image.srcset = image.dataset.srcset;
    delete image.dataset.pose;
  };

  for (const image of document.querySelectorAll(".barry")) {
    let pokes = 0;
    let calm = 0;
    image.addEventListener("click", (event) => {
      if (image.dataset.pose === "sick" || !onTummy(event, image)) return;
      if (!image.dataset.pose) {
        image.dataset.src = image.getAttribute("src");
        image.dataset.srcset = image.getAttribute("srcset") || "";
      }
      if (pokes === 0) for (const pose of ["queasy", "sick"]) new Image().src = `img/barry-${pose}@2x.png`;
      pokes += 1;
      clearTimeout(calm);
      image.classList.remove("poked");
      void image.offsetWidth;
      image.classList.add("poked");

      if (pokes >= 9) {
        pokes = 0;
        image.classList.remove("queasy");
        mood(image, "sick");
        calm = setTimeout(() => settle(image), 4000);
        return;
      }
      if (pokes >= 5) {
        mood(image, "queasy");
        image.classList.add("queasy");
      }
      calm = setTimeout(() => {
        pokes = 0;
        settle(image);
      }, 2200);
    });
    new MutationObserver(() => {
      if (image.dataset.pose && !image.getAttribute("src").includes(`barry-${image.dataset.pose}`)) {
        image.classList.remove("queasy");
        delete image.dataset.pose;
      }
    }).observe(image, { attributes: true, attributeFilter: ["src"] });
  }
}

// Settings

function applyDisplay() {
  const root = document.documentElement;
  if (settings.highContrast) root.dataset.contrast = "high";
  else delete root.dataset.contrast;
  if (settings.largeText) root.dataset.text = "large";
  else delete root.dataset.text;
}

function bindSettings() {
  const dialog = $("settings");
  const fields = {
    "opt-strict": "strict",
    "opt-contrast": "highContrast",
    "opt-large": "largeText",
    "opt-history": "keepHistory",
  };
  for (const [id, key] of Object.entries(fields)) {
    const input = $(id);
    input.checked = Boolean(settings[key]);
    input.addEventListener("change", () => {
      settings[key] = input.checked;
      store(SETTINGS_KEY, settings);
      applyDisplay();
      if (key === "keepHistory") {
        if (!input.checked) store(HISTORY_KEY, []);
        renderHistory();
      }
    });
  }
  const limit = $("opt-limit");
  limit.value = String(settings.maxUnpackedMb);
  limit.addEventListener("change", () => {
    settings.maxUnpackedMb = Number(limit.value);
    store(SETTINGS_KEY, settings);
  });

  const open = (focusAbout) => {
    dialog.showModal();
    if (focusAbout) $("about").scrollIntoView({ block: "start" });
  };
  $("open-settings").addEventListener("click", () => open(false));
  $("open-about").addEventListener("click", () => open(true));
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
}

// Wiring

function bindFilePicking() {
  const input = $("file-input");
  $("choose-file").addEventListener("click", () => input.click());
  input.addEventListener("change", () => {
    const [file] = input.files;
    input.value = "";
    scanFile(file);
  });

  let depth = 0;
  const hasFiles = (event) => Array.from(event.dataTransfer?.types || []).includes("Files");
  window.addEventListener("dragenter", (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    depth += 1;
    document.body.classList.add("dragging");
  });
  window.addEventListener("dragover", (event) => {
    if (hasFiles(event)) event.preventDefault();
  });
  window.addEventListener("dragleave", () => {
    depth = Math.max(0, depth - 1);
    if (depth === 0) document.body.classList.remove("dragging");
  });
  window.addEventListener("drop", (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    depth = 0;
    document.body.classList.remove("dragging");
    scanFile(event.dataTransfer.files[0]);
  });
}

function bindResult() {
  $("check-another").addEventListener("click", () => {
    show("idle", $("choose-file"));
    $("file-input").click();
  });
  $("save-report").addEventListener("click", saveReport);
  $("toggle-details").addEventListener("click", () => {
    const open = $("details").hidden;
    settings.showDetails = open;
    store(SETTINGS_KEY, settings);
    setDetails(open);
  });
  $("cancel-scan").addEventListener("click", () => cancelScan());
  $("clear-recent").addEventListener("click", () => {
    store(HISTORY_KEY, []);
    renderHistory();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || $("settings").open) return;
    if (currentView === "downloads") $("downloads-back").click();
    else if (currentJob) cancelScan();
    else if (!views.result.hidden) show("idle", $("choose-file"));
  });
}

function registerServiceWorker() {
  if (!("serviceWorker" in navigator) || location.protocol === "file:") return;
  navigator.serviceWorker.register("sw.js").catch((error) => console.warn("Offline mode unavailable:", error));
}

applyDisplay();
bindSettings();
bindFilePicking();
bindResult();
bindDownloads();
bindTummy();
renderHistory();
offerDesktopApp();
startWorker();
registerServiceWorker();
