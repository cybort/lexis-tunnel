import { i as __toESM } from "../_runtime.mjs";
import { q as require_react, x as require_jsx_runtime, y as Link } from "../_libs/@tanstack/react-router+[...].mjs";
import { i as Smartphone, o as Monitor, r as Terminal } from "../_libs/lucide-react.mjs";
//#region node_modules/.nitro/vite/services/ssr/assets/download-BLvetMmf.js
var import_react = /* @__PURE__ */ __toESM(require_react());
var import_jsx_runtime = require_jsx_runtime();
var CARDS = [
	{
		id: "windows",
		title: "Windows",
		icon: Monitor,
		resident: "登录任务常驻，失败会重试",
		listen: "固定端口。portproxy 只绑回环，WinDivert 只记录",
		process: "按进程名接入或绕行"
	},
	{
		id: "linux",
		title: "Linux",
		icon: Terminal,
		resident: "systemd 用户服务，断了自己拉起",
		listen: "固定端口。转发脚本可写，tproxy 还取不到原始目的地址",
		process: "从 /proc 认出程序名"
	},
	{
		id: "android",
		title: "Android",
		icon: Smartphone,
		resident: "Termux 后台，Termux:Boot 开机拉起",
		listen: "固定端口。系统接管只写出 VpnService 会话",
		process: "程序规则写在配置里，认不到进程时不乱改动作"
	}
];
function sizeLabel(bytes) {
	if (!bytes) return "";
	if (bytes < 1024) return `${bytes} B`;
	return `${(bytes / 1024).toFixed(1)} KB`;
}
function DownloadPage() {
	const [manifest, setManifest] = (0, import_react.useState)(null);
	(0, import_react.useEffect)(() => {
		let live = true;
		fetch("/downloads/manifest.json").then((res) => res.json()).then((data) => {
			if (live) setManifest(data);
		}).catch(() => {
			if (live) setManifest(null);
		});
		return () => {
			live = false;
		};
	}, []);
	return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
		className: "min-h-screen",
		children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("header", {
			className: "border-b border-line",
			children: /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
				className: "mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-4",
				children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
					className: "flex items-center gap-3",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("span", {
						className: "relative inline-flex h-8 w-8 items-center justify-center",
						"aria-hidden": "true",
						children: [
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "absolute inset-x-1 top-1 h-1.5 bg-sage" }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "absolute inset-x-1 bottom-1 h-1.5 bg-sage" }),
							/* @__PURE__ */ (0, import_jsx_runtime.jsx)("span", { className: "h-1.5 w-1.5 bg-ember" })
						]
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h1", {
						className: "text-xl font-bold tracking-wide",
						children: "词隙"
					}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
						className: "text-sm text-mist",
						children: "下载客户端"
					})] })]
				}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)(Link, {
					to: "/",
					className: "inline-flex min-h-11 items-center text-sm text-sage",
					children: "返回控制台"
				})]
			})
		}), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("main", {
			className: "mx-auto flex max-w-6xl flex-col gap-4 px-4 py-5",
			children: [
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
					className: "rounded-md border border-line bg-panel p-4",
					children: [
						/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
							className: "font-mono text-xs text-sage",
							children: ["LEXIS ", manifest?.version ?? "1.0.0"]
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("h2", {
							className: "mt-2 text-2xl font-bold",
							children: "三个系统，同一份配置"
						}),
						/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
							className: "mt-2 max-w-2xl text-sm text-mist",
							children: "通信进程安装后留在后台。转发正文和控制台是同一套词表。TLS 和 WebSocket 只做外层，用来过 CDN。SOCKS 可以另加用户名。加入名单的节点都能中继。导出的配置带本机私钥，两端要互相放上对方公钥。需要 Node.js 22。状态页在本机 17890 端口。"
						})
					]
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsx)("div", {
					className: "grid gap-3 lg:grid-cols-3",
					children: CARDS.map((card) => {
						const info = manifest?.files[card.id];
						const Icon = card.icon;
						return /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("article", {
							className: "flex flex-col rounded-md border border-line bg-panel p-4",
							children: [
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("div", {
									className: "flex items-center gap-2",
									children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)(Icon, {
										className: "size-5 text-sage",
										"aria-hidden": "true"
									}), /* @__PURE__ */ (0, import_jsx_runtime.jsx)("h3", {
										className: "text-lg font-medium",
										children: card.title
									})]
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("ul", {
									className: "mt-3 flex flex-1 flex-col gap-2 text-sm text-mist",
									children: [
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: card.resident }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: card.listen }),
										/* @__PURE__ */ (0, import_jsx_runtime.jsx)("li", { children: card.process })
									]
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", {
									className: "mt-4 font-mono text-xs text-mist",
									children: info ? `${sizeLabel(info.bytes)} · ${info.sha256.slice(0, 12)}` : "正在读取包信息"
								}),
								/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("a", {
									className: "mt-3 inline-flex min-h-11 items-center justify-center rounded-sm bg-sage px-4 text-sm font-medium text-ink",
									href: info ? `/downloads/${info.file}` : `/downloads/lexis-${card.id}.zip`,
									download: true,
									children: ["下载 ", card.title]
								})
							]
						}, card.id);
					})
				}),
				/* @__PURE__ */ (0, import_jsx_runtime.jsxs)("section", {
					className: "rounded-md border border-line bg-panel p-4 text-sm text-mist",
					children: [/* @__PURE__ */ (0, import_jsx_runtime.jsx)("p", { children: "路由能读 Clash 的逗号规则和 sing-box 的 route.rules。geosite、geoip 内置一份小样，完整库用文本 URL。" }), /* @__PURE__ */ (0, import_jsx_runtime.jsxs)("p", {
						className: "mt-2",
						children: ["先在控制台改好档案。", /* @__PURE__ */ (0, import_jsx_runtime.jsx)("a", {
							href: "/?tab=config",
							className: "ml-2 text-sage",
							children: "打开配置"
						})]
					})]
				})
			]
		})]
	});
}
var SplitComponent = DownloadPage;
//#endregion
export { SplitComponent as component };
