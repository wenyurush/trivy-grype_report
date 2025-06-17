Interactive Vulnerability Report Generator

![alt text](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare)

一个简单而强大的 Web 工具，可将 Grype 和 Trivy 生成的 JSON 扫描报告，转换成美观、可交互的独立 HTML 报告。

✨ 在线体验 »
效果预览

https://report.xecho.org/

核心特性

支持多种工具: 自动检测并解析 Grype 和 Trivy 的 JSON 输出格式。

丰富的数据看板: 以卡片和图表形式直观展示漏洞统计，包括按严重性、软件包、路径和类型分类。

深度交互体验:

点击统计图表，可快速筛选主列表中的漏洞。

内置全文搜索，可快速查找 CVE、软件包、路径等信息。

支持按漏洞等级进行筛选。

单一文件报告: 生成的报告是一个独立的 HTML 文件，包含了所有数据、样式和脚本，易于分享和归档。

纯 Serverless 架构: 前端部署于 Cloudflare Pages，后端逻辑由 Cloudflare Workers 处理，无需管理服务器。

响应式设计: 在桌面和移动设备上均有良好的浏览体验。

技术栈

后端:

Cloudflare Workers: 运行后端逻辑的 Serverless 平台。

Hono: 轻量、快速的 Web 框架，专为边缘计算设计。

TypeScript: 保证代码的类型安全和可维护性。

前端:

Cloudflare Pages: 托管静态前端文件。

原生 HTML, CSS, 和 JavaScript: 无前端框架，极致轻量，加载迅速。

部署:

Wrangler CLI: Cloudflare 官方命令行工具，用于开发和部署。

工作原理

整个流程非常简单直接：

上传: 用户通过 https://report.xecho.org 上的表单上传一个 .json 文件。

处理: 表单将文件 POST 到后端的 Cloudflare Worker (https://api-report.xecho.org/upload)。

解析: Worker 接收到文件后：
a. 检测文件是 Grype 还是 Trivy 格式。
b. 根据对应的格式解析文件，将漏洞信息标准化为统一的数据结构。
c. 计算各种维度的统计数据。

生成: Worker 将解析后的数据和统计信息动态地注入到一个 HTML 模板中，生成一个包含所有内容（数据、CSS、交互式 JS）的完整 HTML 字符串。

响应: Worker 将生成的 HTML 作为响应返回给浏览器。

展示: 浏览器在新标签页中渲染这个 HTML，用户得到一份功能完整的交互式报告。
