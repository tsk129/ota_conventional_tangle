const path = require('path')
const fs = require('fs')

const entryFilePath = path.join(__dirname, '../web/client_wasm.js')
const entryFile = fs.readFileSync(entryFilePath).toString()
// comment out this code so it works for Webpack
let changedFile = entryFile.replace(
    "input = import.meta.url.replace(",
    "// input = import.meta.url.replace("
)
    // Rename original init function, because we want to use the name for our own function
    .replace(
        "async function init(input) {",
        "async function initWasm(input) {"
    )
    .replace(
        "init.__wbindgen_wasm_module = module;",
        "initWasm.__wbindgen_wasm_module = module;"
    )
    // Create an init function which imports the wasm file
    .replace(
        "export default init;",
        "let __initializedIotaWasm = false\r\n\r\nexport function init(path) {\r\n    if (__initializedIotaWasm) {\r\n        return Promise.resolve(wasm)\r\n    }\r\n    return initWasm(path || \'client_wasm_bg.wasm\').then(() => {\r\n        __initializedIotaWasm = true\r\n        return wasm\r\n    })\r\n}\r\n"
    )

fs.writeFileSync(
    entryFilePath,
    changedFile
)

const entryFilePathTs = path.join(__dirname, '../web/client_wasm.d.ts')
const entryFileTs = fs.readFileSync(entryFilePathTs).toString()
// Replace the init function in the ts file
let changedFileTs = entryFileTs.replace(
    "/**\n* If `module_or_path` is {RequestInfo} or {URL}, makes a request and\n* for everything else, calls `WebAssembly.instantiate` directly.\n*\n* @param {InitInput | Promise<InitInput>} module_or_path\n*\n* @returns {Promise<InitOutput>}\n*/\nexport default function init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;",
    "\/**\r\n* Loads the Wasm file so the lib can be used, relative path to Wasm file\r\n* @param {string | undefined} path\r\n*\/\r\nexport function init (path?: string): Promise<void>;"
)
fs.writeFileSync(
    entryFilePathTs,
    changedFileTs
)
