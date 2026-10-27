// Preloaded into help/invalid-option subprocesses. Record attempts even when
// application code catches the thrown error, and prevent them from happening.
const fs = require("node:fs");
const { syncBuiltinESMExports } = require("node:module");
const append = fs.appendFileSync.bind(fs);
const deny = (operation) => () => {
  append(process.env.CASE_EFFECT_LOG, operation + "\n");
  throw new Error(`unexpected command effect: ${operation}`);
};

globalThis.fetch = deny("fetch");
for (const name of ["node:http", "node:https"]) {
  const api = require(name);
  for (const method of ["request", "get"]) api[method] = deny(`${name}.${method}`);
}
require("node:net").Socket.prototype.connect = deny("socket.connect");
require("node:net").Server.prototype.listen = deny("server.listen");
require("node:tls").connect = deny("tls.connect");
require("node:dgram").createSocket = deny("dgram.createSocket");
const childProcess = require("node:child_process");
for (const method of ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"]) {
  childProcess[method] = deny(`child_process.${method}`);
}

for (const method of ["appendFile", "writeFile", "mkdir", "mkdtemp", "rm", "rmdir", "unlink", "rename", "copyFile", "cp", "symlink", "link", "truncate", "chmod", "chown", "utimes"]) {
  for (const api of [fs, fs.promises]) {
    if (typeof api[method] === "function") api[method] = deny(`fs.${method}`);
  }
  if (typeof fs[`${method}Sync`] === "function") fs[`${method}Sync`] = deny(`fs.${method}Sync`);
}
fs.createWriteStream = deny("fs.createWriteStream");
for (const [api, name] of [[fs, "open"], [fs, "openSync"], [fs.promises, "open"]]) {
  const original = api[name].bind(api);
  api[name] = (file, flags, ...args) => {
    const writes = typeof flags === "number"
      ? (flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_APPEND)) !== 0
      : /[wa+]/.test(flags);
    if (writes) return deny(`fs.${name}(write)`)();
    return original(file, flags, ...args);
  };
}
syncBuiltinESMExports();
