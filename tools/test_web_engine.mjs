// Anti-Logging Bear by Priest

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const site = path.resolve(process.argv[2] || path.join(root, "build", "web"));
const wheels = path.resolve(process.argv[3] || path.join(root, ".cache", "web", "test-wheels"));

const { loadPyodide } = await import(pathToFileURL(path.join(site, "pyodide", "pyodide.mjs")).href);
const pyodide = await loadPyodide({ indexURL: path.join(site, "pyodide") + path.sep });
await pyodide.loadPackage("pyyaml", { messageCallback: () => {} });

const sitePackages = pyodide.runPython("import site; site.getsitepackages()[0]");
const unpack = (file) => pyodide.unpackArchive(new Uint8Array(fs.readFileSync(file)), "zip", { extractDir: sitePackages });
unpack(path.join(site, "py", "barry.zip"));
for (const wheel of fs.readdirSync(wheels).filter((name) => name.endsWith(".whl"))) {
  unpack(path.join(wheels, wheel));
}

pyodide.FS.mkdirTree("/project/tests");
for (const name of fs.readdirSync(path.join(root, "tests")).filter((file) => file.endsWith(".py"))) {
  pyodide.FS.writeFile(`/project/tests/${name}`, fs.readFileSync(path.join(root, "tests", name)));
}
pyodide.FS.mkdirTree("/project/tests/fixtures");
for (const name of fs.readdirSync(path.join(root, "tests", "fixtures"))) {
  pyodide.FS.writeFile(`/project/tests/fixtures/${name}`, fs.readFileSync(path.join(root, "tests", "fixtures", name)));
}

const status = pyodide.runPython(`
import os, sys, pytest
os.chdir("/project")
sys.path.insert(0, "/project/tests")
int(pytest.main(["-q", "-p", "no:cacheprovider", "tests/test_scanner.py", "tests/test_web.py", "tests/test_unpacking.py"]))
`);
process.exit(status);
