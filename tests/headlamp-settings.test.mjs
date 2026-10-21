import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runInNewContext } from "node:vm";

const source = readFileSync(new URL("../deploy/headlamp/main.js", import.meta.url), "utf8");
function load(saved, { unavailable = false } = {}) {
  const storage = new Map(saved === undefined ? [] : [["cluster_settings.main", saved]]);
  const routes = [];
  const context = {
    window: {
      localStorage: {
        getItem(key) { return storage.get(key) ?? null; },
        setItem(key, value) {
          if (unavailable) throw new Error("private storage detail");
          storage.set(key, value);
        },
      },
      pluginLib: {
        React: { createElement() {} },
        registerRoute(value) { routes.push(value); },
        registerSidebarEntry() {},
      },
    },
  };
  runInNewContext(source, context);
  return { settings: JSON.parse(storage.get("cluster_settings.main")), routes };
}

test("a fresh viewer lists only the namespaces covered by its RoleBindings", () => {
  const { settings, routes } = load();
  assert.deepEqual(settings.allowedNamespaces, ["security-lab", "spire-system"]);
  assert.equal(settings.defaultNamespace, "security-lab");
  assert.equal(routes.length, 1);
});

test("existing presentation settings survive while broad namespace selection is replaced", () => {
  const { settings } = load(JSON.stringify({
    appearance: { accentColor: "blue" },
    allowedNamespaces: ["kube-system"],
    allowedNamespacesSelector: "match=everything",
    defaultNamespace: "kube-system",
  }));
  assert.deepEqual(settings.appearance, { accentColor: "blue" });
  assert.deepEqual(settings.allowedNamespaces, ["security-lab", "spire-system"]);
  assert.equal(settings.defaultNamespace, "security-lab");
  assert.equal(settings.allowedNamespacesSelector, undefined);
});

test("a valid lab default namespace is preserved", () => {
  assert.equal(load(JSON.stringify({ defaultNamespace: "spire-system" })).settings.defaultNamespace, "spire-system");
});

for (const saved of ["broken-json", "null", "[]", '"text"']) {
  test(`invalid saved settings are replaced safely: ${saved}`, () => {
    assert.deepEqual(load(saved).settings.allowedNamespaces, ["security-lab", "spire-system"]);
  });
}

test("unavailable storage reports a fixed error without leaking browser details", () => {
  assert.throws(() => load(undefined, { unavailable: true }), {
    message: "Local viewer namespace settings are unavailable",
  });
});
