'use strict';

/*
 * Frida helper for authorized Android reverse engineering.
 * It dumps readable ranges belonging to one loaded module and writes a JSON manifest.
 * The output is intentionally range-based; later tools can stitch/rebuild it without
 * pretending unreadable gaps were valid bytes.
 */

function hex(v) {
  return '0x' + ptr(v).toString(16);
}

function safeName(name) {
  return name.replace(/[^A-Za-z0-9._-]+/g, '_');
}

function dumpModule(moduleName, outputDir) {
  const mod = Process.getModuleByName(moduleName);
  const dir = outputDir || '/sdcard/Download/mobile-ghidra-runtime';
  const prefix = safeName(moduleName) + '-' + mod.base.toString(16);
  const manifest = {
    module: moduleName,
    base: hex(mod.base),
    size: mod.size,
    path: mod.path,
    ranges: []
  };

  const protections = ['r--', 'rw-', 'r-x', 'rwx'];
  const seen = {};
  let index = 0;

  protections.forEach(function (protection) {
    mod.enumerateRanges(protection).forEach(function (range) {
      const key = range.base.toString() + ':' + range.size;
      if (seen[key]) return;
      seen[key] = true;

      const relative = range.base.sub(mod.base);
      const fileName = prefix + '-range-' + String(index).padStart(4, '0') + '.bin';
      const fullPath = dir + '/' + fileName;
      let status = 'ok';
      let error = null;
      try {
        const bytes = range.base.readByteArray(range.size);
        const f = new File(fullPath, 'wb');
        f.write(bytes);
        f.flush();
        f.close();
      } catch (e) {
        status = 'error';
        error = String(e);
      }

      manifest.ranges.push({
        index: index,
        file: fileName,
        base: hex(range.base),
        relative_offset: hex(relative),
        size: range.size,
        protection: range.protection,
        status: status,
        error: error
      });
      index += 1;
    });
  });

  const manifestPath = dir + '/' + prefix + '-manifest.json';
  const mf = new File(manifestPath, 'w');
  mf.write(JSON.stringify(manifest, null, 2));
  mf.flush();
  mf.close();

  return {
    module: moduleName,
    base: manifest.base,
    size: manifest.size,
    manifest: manifestPath,
    dumped_ranges: manifest.ranges.filter(r => r.status === 'ok').length,
    failed_ranges: manifest.ranges.filter(r => r.status !== 'ok').length
  };
}

rpc.exports = {
  listmodules: function () {
    return Process.enumerateModules().map(function (m) {
      return { name: m.name, base: hex(m.base), size: m.size, path: m.path };
    });
  },
  dumpmodule: function (moduleName, outputDir) {
    return dumpModule(moduleName, outputDir);
  }
};
