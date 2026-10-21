(function () {
	"use strict";
	// Headlamp otherwise lists namespaced resources at cluster scope. These are
	// display defaults only; Kubernetes RBAC remains the authorization boundary.
	const namespaces = ["security-lab", "spire-system"];
	const settingsKey = "cluster_settings.main";
	let settings = {};
	try {
		const saved = JSON.parse(window.localStorage.getItem(settingsKey) || "{}");
		if (saved && typeof saved === "object" && !Array.isArray(saved)) {
			settings = saved;
		}
	} catch {
		// Invalid or unavailable browser state must never broaden server access.
	}
	settings.allowedNamespaces = namespaces;
	delete settings.allowedNamespacesSelector;
	if (!namespaces.includes(settings.defaultNamespace)) {
		settings.defaultNamespace = namespaces[0];
	}
	try {
		window.localStorage.setItem(settingsKey, JSON.stringify(settings));
	} catch {
		throw new Error("Local viewer namespace settings are unavailable");
	}
	const { React, registerRoute, registerSidebarEntry } = window.pluginLib;
	const h = React.createElement;
	const palette = {
		ink: "#202c38",
		muted: "#617181",
		paper: "#f5f7fa",
		border: "#dde5ec",
		blue: "#285e93",
		green: "#24745b",
		red: "#ac4242",
	};
	const panels = ["Services", "Trust map", "Permissions", "Audit", "Demo"];
	const card = {
		background: "white",
		border: `1px solid ${palette.border}`,
		borderRadius: 16,
		padding: 22,
	};
	const small = { color: palette.muted, fontSize: 13 };
	function badge(value, good) {
		return h(
			"span",
			{
				style: {
					display: "inline-block",
					padding: "4px 9px",
					whiteSpace: "nowrap",
					borderRadius: 6,
					fontSize: 12,
					fontWeight: 600,
					color: good ? palette.green : palette.red,
					background: good ? "#e8f4ed" : "#fceeee",
				},
			},
			value,
		);
	}
	function table(headers, rows) {
		return h(
			"div",
			{ style: { overflowX: "auto" } },
			h(
				"table",
				{
					style: {
						width: "100%",
						minWidth: 760,
						borderCollapse: "collapse",
						fontSize: 14,
					},
				},
				h(
					"thead",
					null,
					h(
						"tr",
						null,
						...headers.map((label) =>
							h(
								"th",
								{
									key: label,
									scope: "col",
									style: {
										textAlign: "left",
										padding: "14px 12px",
										color: palette.muted,
										borderBottom: `1px solid ${palette.border}`,
										fontWeight: 500,
										whiteSpace: "nowrap",
									},
								},
								label,
							),
						),
					),
				),
				h(
					"tbody",
					null,
					...rows.map((row, i) =>
						h(
							"tr",
							{ key: i },
							...row.map((cell, j) =>
								h(
									"td",
									{
										key: j,
										style: {
											padding: "15px 12px",
											borderBottom: `1px solid ${palette.border}`,
											verticalAlign: "top",
											wordBreak: "normal",
											overflowWrap: "anywhere",
										},
									},
									cell,
								),
							),
						),
					),
				),
			),
		);
	}
	function box(title, content, note) {
		return h(
			"section",
			{ style: card },
			h("h2", { style: { fontSize: 19, margin: "0 0 12px" } }, title),
			note && h("p", { style: small }, note),
			content,
		);
	}
	function Services({ data }) {
		return box(
			"Running services",
			table(
				["Service", "Purpose", "Namespace", "State", "Restarts"],
				data.services.map((s) => [
					h(
						"div",
						null,
						h("strong", null, s.name),
						h("div", { style: { ...small, marginTop: 4 } }, s.project),
					),
					s.role,
					s.namespace,
					badge(
						`${s.ready}/${s.desired} ready`,
						s.ready === s.desired && s.desired > 0,
					),
					s.restarts,
				]),
			),
			"Observed from Kubernetes. The bridge is a library inside the FHIR gateway, not another daemon.",
		);
	}
	function Trust({ data }) {
		const steps = [
			[
				"01",
				"SPIRE",
				"Attests the node and workload ServiceAccounts. Issues short-lived identities.",
			],
			[
				"02",
				"Research agent",
				"Uses its JWT-SVID to request access for one target service.",
			],
			[
				"03",
				"Authorization server",
				"Checks the allowlist and issues a resource-bound token for 300 seconds.",
			],
			[
				"04",
				"SPIFFE bridge",
				"Verifies mTLS and requires the access-token subject to match the caller.",
			],
			[
				"05",
				"FHIR tools",
				"Run the permitted read operation and record the verified caller in audit.",
			],
		];
		return h(
			"div",
			{ style: { display: "grid", gap: 18 } },
			box(
				"How a request travels",
				h(
					"div",
					{
						style: {
							display: "grid",
							gridTemplateColumns: "repeat(auto-fit, minmax(165px, 1fr))",
							gap: 12,
						},
					},
					...steps.map(([number, title, detail]) =>
						h(
							"div",
							{
								key: number,
								style: {
									background: palette.paper,
									borderRadius: 12,
									padding: 18,
								},
							},
							h(
								"div",
								{ style: { color: palette.blue, fontSize: 12 } },
								number,
							),
							h("h3", { style: { fontSize: 16 } }, title),
							h("p", { style: { ...small, lineHeight: 1.65 } }, detail),
						),
					),
				),
			),
			box(
				"Configured SPIFFE identities",
				table(
					["Workload", "SPIFFE ID", "Attestation"],
					data.identities.map((i) => [
						i.workload,
						h("code", { style: { fontSize: 12 } }, i.id),
						`${i.namespace} / ${i.account}`,
					]),
				),
				"Registration configuration, not a list of currently issued certificates. Copying labels does not copy a ServiceAccount identity.",
			),
		);
	}
	function Permissions({ data }) {
		return box(
			"Authorization allowlist",
			table(
				["Caller", "Resource", "Scopes"],
				data.permissions.map((p) => [
					h("code", { style: { fontSize: 12 } }, p.caller),
					h("code", { style: { fontSize: 12 } }, p.resource),
					p.scopes.join(", "),
				]),
			),
			"Snapshot of the actual lab policy file. A revoked grant blocks new tokens; already issued tokens may remain usable for up to 300 seconds.",
		);
	}
	function Audit({ data }) {
		return box(
			"Recent access decisions",
			data.audit.length
				? table(
						["Time (UTC)", "Service", "Outcome", "Verified identity"],
						data.audit.map((a) => [
							new Date(a.at).toLocaleTimeString("en-GB", { timeZone: "UTC" }),
							a.source,
							badge(
								a.outcome,
								a.outcome === "allow" ||
									a.outcome === "success" ||
									a.outcome === "issued",
							),
							a.caller || "Not included",
						]),
					)
				: h(
						"p",
						{ style: small },
						"No retained decisions in the current processes. Run the demo to populate this view.",
					),
			"Latest bounded log window. Only timestamps, fixed outcomes and allowlisted identities are shown. This view is not durable audit storage or an integrity verifier.",
		);
	}
	function Demo({ data }) {
		const demo = data.demo;
		if (!demo)
			return box(
				"Integration scenarios",
				h(
					"p",
					{ style: small },
					"No complete local result is available yet. Run make demo to validate the stack.",
				),
			);
		return box(
			"Integration scenarios",
			h(
				"div",
				null,
				h(
					"div",
					{
						style: {
							display: "flex",
							gap: 12,
							alignItems: "center",
							marginBottom: 18,
						},
					},
					badge(
						demo.passed ? "All 18 passed" : "Incomplete or failed",
						demo.passed,
					),
					h(
						"span",
						{ style: small },
						`Report started ${new Date(demo.at).toLocaleString("en-GB", { timeZone: "UTC" })} UTC`,
					),
				),
				table(
					["Scenario", "Check", "Result"],
					demo.results.map((r) => [
						String(r.number).padStart(2, "0"),
						r.title,
						badge(r.passed ? "Pass" : "Not passed", r.passed),
					]),
				),
			),
			"A dated validation report, not a continuous health check. Results remain visible after service restarts.",
		);
	}
	function Lab() {
		const [data, setData] = React.useState(null);
		const [error, setError] = React.useState(false);
		const [tab, setTab] = React.useState(0);
		const [request, setRequest] = React.useState(0);
		React.useEffect(() => {
			let live = true;
			let controller;
			let busy = false;
			async function load() {
				if (busy) return;
				busy = true;
				controller = new AbortController();
				const timeout = setTimeout(() => controller.abort(), 20000);
				try {
					const response = await fetch("/_lab/snapshot", {
						signal: controller.signal,
						cache: "no-store",
					});
					if (!response.ok) throw new Error("unavailable");
					const value = await response.json();
					if (live) {
						setData(value);
						setError(false);
					}
				} catch {
					if (live) setError(true);
				} finally {
					clearTimeout(timeout);
					busy = false;
				}
			}
			load();
			const interval = setInterval(load, 15000);
			return () => {
				live = false;
				clearInterval(interval);
				controller?.abort();
			};
		}, [request]);
		const ready =
			data?.services.filter((s) => s.ready === s.desired && s.desired > 0)
				.length || 0;
		const views = [Services, Trust, Permissions, Audit, Demo];
		return h(
			"main",
			{
				className: "security-lab-view",
				style: {
					color: palette.ink,
					background: palette.paper,
					borderRadius: 18,
					padding: "clamp(18px, 3vw, 34px)",
					maxWidth: 1280,
					margin: "0 auto",
					fontFamily: "system-ui, sans-serif",
				},
			},
			h(
				"header",
				{
					style: {
						display: "flex",
						gap: 18,
						justifyContent: "space-between",
						flexWrap: "wrap",
						marginBottom: 24,
					},
				},
				h(
					"div",
					null,
					h(
						"div",
						{
							style: { ...small, letterSpacing: 2, textTransform: "uppercase" },
						},
						"Local security workspace",
					),
					h("h1", { style: { fontSize: 30, margin: "8px 0" } }, "Security lab"),
					h(
						"p",
						{ style: { ...small, margin: 0 } },
						"Lima / Kubernetes / containerd / SPIRE",
					),
				),
				h(
					"div",
					{
						style: {
							display: "flex",
							flexWrap: "wrap",
							alignItems: "center",
							gap: 12,
						},
					},
					badge("Read-only", true),
					data?.viewer && badge("ZITADEL viewer", true),
					data?.viewer &&
						h(
							"button",
							{
								type: "button",
								onClick: async () => {
									const result = await fetch("/_auth/logout", {
										method: "POST",
										credentials: "same-origin",
									});
									if (result.ok) window.location.assign("/");
								},
								style: {
									background: "white",
									border: `1px solid ${palette.border}`,
									borderRadius: 9,
									padding: "10px 15px",
									cursor: "pointer",
									color: palette.ink,
								},
							},
							"Sign out",
						),
					h(
						"button",
						{
							type: "button",
							onClick: () => setRequest((n) => n + 1),
							style: {
								background: "white",
								border: `1px solid ${palette.border}`,
								borderRadius: 9,
								padding: "10px 15px",
								cursor: "pointer",
								color: palette.ink,
							},
						},
						"Refresh",
					),
				),
			),
			error &&
				h(
					"div",
					{
						role: "alert",
						style: {
							...card,
							borderColor: palette.red,
							marginBottom: 18,
							color: palette.red,
						},
					},
					data
						? "Connection unavailable. The information below is a previous snapshot, not current status."
						: "The lab is unavailable. Start it with make ui.",
				),
			data
				? h(
						React.Fragment,
						null,
						h(
							"div",
							{
								style: {
									display: "grid",
									gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
									gap: 14,
									marginBottom: 24,
								},
							},
							...[
								["Services ready", `${ready} / ${data.services.length}`],
								[
									"Guest memory",
									`${(data.memory.used_mib / 1024).toFixed(2)} GiB`,
								],
								["VM memory cap", "4 GiB"],
								[
									"Last demo",
									data.demo?.passed ? "18 / 18 passed" : "Not complete",
								],
							].map(([title, value]) =>
								h(
									"div",
									{ key: title, style: card },
									h("div", { style: small }, title),
									h(
										"div",
										{ style: { fontSize: 24, fontWeight: 600, marginTop: 10 } },
										value,
									),
								),
							),
						),
						h(
							"nav",
							{
								role: "tablist",
								"aria-label": "Security lab sections",
								style: {
									display: "flex",
									overflowX: "auto",
									gap: 7,
									marginBottom: 18,
								},
							},
							...panels.map((label, i) =>
								h(
									"button",
									{
										key: label,
										id: `lab-tab-${i}`,
										role: "tab",
										type: "button",
										"aria-selected": tab === i,
										"aria-controls": "lab-panel",
										onClick: () => setTab(i),
										style: {
											border: 0,
											borderRadius: 9,
											padding: "12px 18px",
											fontSize: 14,
											fontWeight: 500,
											whiteSpace: "nowrap",
											background: tab === i ? palette.blue : "white",
											color: tab === i ? "white" : palette.muted,
											cursor: "pointer",
										},
									},
									label,
								),
							),
						),
						h(
							"div",
							{
								role: "tabpanel",
								id: "lab-panel",
								"aria-labelledby": `lab-tab-${tab}`,
							},
							h(views[tab], { data }),
						),
						h(
							"footer",
							{ style: { ...small, marginTop: 20, lineHeight: 1.65 } },
							`Observed ${new Date(data.at).toLocaleTimeString("en-GB", { timeZone: "UTC" })} UTC. Refreshes every 15 seconds. `,
							"Synthetic lab; guest memory excludes macOS overhead. ECS is excluded.",
						),
					)
				: !error &&
						h(
							"p",
							{ role: "status", style: small },
							"Reading the local lab...",
						),
		);
	}
	registerSidebarEntry({
		parent: null,
		name: "security-lab",
		label: "Security lab",
		url: "/security-lab",
		icon: "mdi:shield-check-outline",
	});
	registerRoute({
		path: "/security-lab",
		name: "security-lab",
		sidebar: "security-lab",
		exact: true,
		component: Lab,
	});
})();
