// Anti-Logging Bear by Priest

import { loadPyodide } from "./pyodide/pyodide.mjs";

const SCAN_DIR = "/scan";

const engine = (async () => {
  const pyodide = await loadPyodide({ indexURL: new URL("./pyodide/", import.meta.url).href });
  await pyodide.loadPackage("pyyaml", { messageCallback: () => {} });
  const response = await fetch(new URL("./py/barry.zip", import.meta.url));
  if (!response.ok) throw new Error(`Couldn't load Barry's checks (${response.status})`);
  const site = pyodide.runPython("import site; site.getsitepackages()[0]");
  pyodide.unpackArchive(await response.arrayBuffer(), "zip", { extractDir: site });
  pyodide.FS.mkdirTree(SCAN_DIR);
  const bridge = pyodide.pyimport("barry_web");
  return { pyodide, bridge };
})();

engine.then(
  ({ bridge }) => postMessage({ type: "ready", version: bridge.__version__ }),
  (error) => postMessage({ type: "fatal", message: String(error && error.message || error) }),
);

self.onmessage = async ({ data: job }) => {
  if (job.type !== "scan") return;
  let path = null;
  try {
    const { pyodide, bridge } = await engine;
    path = `${SCAN_DIR}/${fileName(job.name)}`;
    pyodide.FS.writeFile(path, new Uint8Array(job.buffer));
    let checked = 0;
    const progress = (text) => {
      checked += 1;
      postMessage({ type: "progress", id: job.id, text, checked });
    };
    const json = bridge.scan.callKwargs(path, {
      strict: job.options.strict,
      max_unpacked_mb: job.options.maxUnpackedMb,
      progress,
    });
    postMessage({ type: "result", id: job.id, report: JSON.parse(json) });
  } catch (error) {
    postMessage({ type: "error", id: job.id, message: String(error && error.message || error) });
  } finally {
    if (path) {
      const { pyodide } = await engine;
      try { pyodide.FS.unlink(path); } catch { /* already gone */ }
    }
  }
};

function fileName(name) {
  const cleaned = String(name || "").replace(/[\/\0]/g, "_");
  return cleaned === "" || cleaned === "." || cleaned === ".." ? "download" : cleaned;
}
