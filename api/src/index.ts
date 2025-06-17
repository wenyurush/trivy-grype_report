// 文件路径: api/src/index.ts (完整修正版)

import { Hono } from 'hono';
import { cors } from 'hono/cors'; // <--- 1. 引入 cors


// ===============================================
// 1. 创建 Hono 应用并定义路由
// ===============================================

const app = new Hono();

app.use('/upload', cors({
  origin: 'https://report.xecho.org', // <--- 3. 明确允许你的前端域名
  allowMethods: ['POST', 'OPTIONS'], // 允许的方法
}));


// 定义 /upload 路由，只接受 POST 请求
app.post('/upload', async (c) => {
  try {
    const formData = await c.req.formData();
    const file = formData.get('report_file') as File;

    if (!file) {
      return c.text('File not provided', 400);
    }
    if (!file.name.endsWith('.json')) {
        return c.text('Invalid file type. Please upload a .json file.', 400);
    }

    const content = await file.text();
    const data = JSON.parse(content);

    const format = detectFormat(data);
    let vulnerabilities: Vulnerability[] = [];
    let toolName = 'Unknown';

    if (format === 'grype') {
      vulnerabilities = parseGrypeJson(data);
      toolName = 'Grype';
    } else if (format === 'trivy') {
      vulnerabilities = parseTrivyJson(data);
      toolName = 'Trivy';
    } else {
      return c.text('Invalid or unknown JSON format. Please upload a valid Grype or Trivy report.', 400);
    }

    const htmlReport = generateHtmlReport(vulnerabilities, toolName);
    
    return c.html(htmlReport); // Hono 的便捷方法，自动设置 Content-Type 为 text/html

  } catch (e) {
    const error = e instanceof Error ? e.message : 'An unknown error occurred';
    return c.text(`Error processing file: ${error}`, 500);
  }
});

// 定义根路由，用于健康检查或欢迎信息
app.get('/', (c) => {
    return c.text('Vulnerability Reporter API is running!');
});

// ===============================================
// 2. 数据结构定义 (TypeScript)
// ===============================================

interface Vulnerability {
  id: string;
  package: string;
  version: string;
  severity: string;
  fixed_version: string;
  location: string;
  type: string;
  description: string;
}

interface Stats {
  by_severity: Record<string, number>;
  by_location: [string, Record<string, any>][];
  by_package: [string, Record<string, any>][];
  by_type: [string, Record<string, any>][];
}

// ===============================================
// 3. 核心解析和统计逻辑
// ===============================================

const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN'];
const STATS_SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function detectFormat(data: any): 'trivy' | 'grype' | 'unknown' {
  if (data && typeof data === 'object') {
    if ('Results' in data && Array.isArray(data.Results)) return 'trivy';
    if ('matches' in data && Array.isArray(data.matches)) return 'grype';
  }
  return 'unknown';
}

function parseTrivyJson(data: any): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  for (const result of data.Results || []) {
    for (const vuln of result.Vulnerabilities || []) {
      vulnerabilities.push({
        id: vuln.VulnerabilityID || 'N/A',
        package: vuln.PkgName || 'N/A',
        version: vuln.InstalledVersion || 'N/A',
        severity: (vuln.Severity || 'UNKNOWN').toUpperCase(),
        fixed_version: vuln.FixedVersion || 'N/A',
        location: result.Target || 'Unknown',
        type: result.Type || 'Unknown',
        description: vuln.Description || '',
      });
    }
  }
  return vulnerabilities;
}

function parseGrypeJson(data: any): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];
  for (const match of data.matches || []) {
    const vuln = match.vulnerability || {};
    const artifact = match.artifact || {};
    const location = (artifact.locations && artifact.locations[0]?.path) || 'N/A';
    vulnerabilities.push({
      id: vuln.id || 'N/A',
      package: artifact.name || 'N/A',
      version: artifact.version || 'N/A',
      severity: (vuln.severity || 'UNKNOWN').toUpperCase(),
      fixed_version: vuln.fix?.versions?.join(', ') || 'N/A',
      location: location,
      type: artifact.type || 'Unknown',
      description: vuln.description || '',
    });
  }
  return vulnerabilities;
}

function calculateStatistics(vulnerabilities: Vulnerability[]): Stats {
    const stats: any = {
        by_severity: {},
        by_location: {},
        by_package: {},
        by_type: {}
    };
    SEVERITY_LEVELS.forEach(s => stats.by_severity[s] = 0);

    vulnerabilities.forEach(vuln => {
        const severity = SEVERITY_LEVELS.includes(vuln.severity) ? vuln.severity : 'UNKNOWN';
        stats.by_severity[severity]++;

        for (const key of ['location', 'package', 'type'] as const) {
            const mapKey = `by_${key}`;
            const value = vuln[key];
            if (!stats[mapKey][value]) {
                stats[mapKey][value] = { _total: 0 };
                SEVERITY_LEVELS.forEach(s => stats[mapKey][value][s] = 0);
            }
            stats[mapKey][value][severity]++;
            stats[mapKey][value]._total++;
        }
    });
    
    for (const key of ['location', 'package', 'type']) {
        stats[`by_${key}`] = Object.entries(stats[`by_${key}`]).sort((a: any, b: any) => b[1]._total - a[1]._total);
    }
    return stats;
}

// ===============================================
// 4. HTML 报告生成 (已修正)
// ===============================================

function escapeHtml(str: string = ''): string {
  return str.replace(/&/g, "&")
            .replace(/</g, "<")
            .replace(/>/g, ">")
            .replace(/"/g, '"')
            .replace(/'/g, '\'');
}

function jsSafeEscape(text: string): string {
  return text.replace(/\\/g, '\\\\')
             .replace(/'/g, "\\'")
             .replace(/"/g, '\\"');
}

function buildSummaryCards(stats: Stats): string {
    const total = Object.values(stats.by_severity).reduce((a, b) => a + b, 0);
    let cards = `<div class="summary-item summary-total" onclick="setSeverityFilter('')"><div class="summary-number">${total}</div><div class="summary-label">Total</div></div>`;
    STATS_SEVERITIES.forEach(sev => {
        const count = stats.by_severity[sev] || 0;
        cards += `<div class="summary-item summary-${sev.toLowerCase()}" onclick="setSeverityFilter('${sev}')"><div class="summary-number">${count}</div><div class="summary-label">${sev}</div></div>`;
    });
    return cards;
}

function buildStatsTableWithFilter(data: [string, any][], keyHeader: string, filterType: string, tableId: string, controlsId: string): string {
    let htmlParts = `<div id="${controlsId}" class="stats-filter-controls"><strong>Show items with:</strong>`;
    STATS_SEVERITIES.forEach(sev => {
         htmlParts += `<label><input type="checkbox" value="${sev.toLowerCase()}"> ${sev}</label>`;
    });
    htmlParts += `</div><div class="stats-table-wrapper">`;
    const headerCols = STATS_SEVERITIES.map(s => `<th class='count-cell'>${s[0]}</th>`).join('');
    htmlParts += `<table id="${tableId}" class="stats-table"><thead><tr><th>${keyHeader}</th><th class='count-cell'>Total</th>${headerCols}</tr></thead><tbody>`;
    for (const [key, counts] of data) {
        const jsSafeKey = jsSafeEscape(key);
        const dataAttrs = STATS_SEVERITIES.map(s => `data-${s.toLowerCase()}-count="${counts[s] || 0}"`).join(' ');
        const countCells = STATS_SEVERITIES.map(s => `<td class="count-cell">${counts[s] || 0}</td>`).join('');
        htmlParts += `<tr class="clickable" onclick="setDimensionalFilter('${filterType}', '${jsSafeKey}')" ${dataAttrs}>
                        <td style="word-break: break-all;">${escapeHtml(key)}</td>
                        <td class="count-cell">${counts._total || 0}</td>
                        ${countCells}
                    </tr>`;
    }
    htmlParts += '</tbody></table></div>';
    return data.length > 0 ? htmlParts : "<p style='padding:15px;'>No data</p>";
}

function buildTypeStatsTable(data: [string, any][]): string {
    const headerCols = STATS_SEVERITIES.map(s => `<th class='count-cell'>${s}</th>`).join('');
    let rowsHtml = `<thead><tr><th>Type</th><th class='count-cell'>Total</th>${headerCols}</tr></thead><tbody>`;
    for (const [key, counts] of data) {
        const jsSafeKey = jsSafeEscape(key);
        const total = counts._total || 0;
        let row = `<tr><td><span class="type-badge">${escapeHtml(key)}</span></td>`;
        row += total > 0 ? `<td class="count-cell clickable-cell" onclick="setTypedFilter('${jsSafeKey}', '')">${total}</td>` : `<td class="count-cell">${total}</td>`;
        STATS_SEVERITIES.forEach(sev => {
            const count = counts[sev] || 0;
            row += count > 0 ? `<td class="count-cell clickable-cell" onclick="setTypedFilter('${jsSafeKey}', '${sev}')">${count}</td>` : `<td class="count-cell">${count}</td>`;
        });
        row += '</tr>';
        rowsHtml += row;
    }
    rowsHtml += '</tbody>';
    return data.length > 0 ? rowsHtml : "<tbody><tr><td colspan='6' style='padding:15px;'>No data</td></tr></tbody>";
}

function generateHtmlReport(vulnerabilities: Vulnerability[], scanTool: string): string {
    const stats = calculateStatistics(vulnerabilities);
    const totalVulns = vulnerabilities.length;
    const timestamp = new Date().toISOString();

    const tableRows = vulnerabilities.map(vuln => `
        <tr data-type="${escapeHtml(vuln.type)}" data-location="${escapeHtml(vuln.location)}">
            <td><strong>${escapeHtml(vuln.id)}</strong></td>
            <td class="package-name">${escapeHtml(vuln.package)}</td>
            <td class="version">${escapeHtml(vuln.version)}</td>
            <td><span class="severity-badge severity-${vuln.severity.toLowerCase()}">${escapeHtml(vuln.severity)}</span></td>
            <td class="version">${escapeHtml(vuln.fixed_version)}</td>
            <td><span class="type-badge">${escapeHtml(vuln.type)}</span></td>
            <td class="location">${escapeHtml(vuln.location)}</td>
            <td class="description">${escapeHtml(vuln.description)}</td>
        </tr>`).join('');

    const severityOptions = [...STATS_SEVERITIES, 'NEGLIGIBLE'].map(s => `<option value='${s}'>${s}</option>`).join('');

    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${scanTool} Vulnerability Report</title>
        <style>
            * { box-sizing: border-box; }
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f4f7f9; }
            .container { max-width: 1600px; margin: 0 auto; background: white; padding: 30px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
            h1, h2 { color: #2c3e50; text-align: center; }
            h1 { font-size: 2.2em; margin-bottom: 20px; }
            h2 { font-size: 1.5em; margin-top: 30px; margin-bottom: 15px; border-bottom: 2px solid #ecf0f1; padding-bottom: 8px; text-align:left; }
            .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 15px; margin-bottom: 30px; }
            .summary-item { text-align: center; padding: 15px; border-radius: 8px; color: white; box-shadow: 0 4px 10px rgba(0,0,0,0.1); transition: transform 0.3s ease; cursor: pointer; user-select: none; font-size: 0.9em;}
            .summary-item:hover { transform: translateY(-5px); }
            .summary-total { background: #3498db; } .summary-critical { background: #e74c3c; } .summary-high { background: #f39c12; } .summary-medium { background: #f1c40f; color: #2c3e50; } .summary-low { background: #27ae60; }
            .summary-number { font-size: 22px; font-weight: bold; } .summary-label { font-size: 13px; margin-top: 5px; }
            .stats-layout { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;}
            @media (max-width: 1000px) { .stats-layout { grid-template-columns: 1fr; } }
            .stats-full-width { grid-column: 1 / -1; }
            details { border: 1px solid #ddd; border-radius: 8px; overflow: hidden; background:#fff; }
            summary { font-weight: bold; font-size: 1.1em; padding: 12px; background: #f8f9fa; cursor: pointer; color: #2c3e50;}
            summary:hover { background: #ecf0f1;}
            .stats-table-wrapper { max-height: 350px; overflow-y: auto; }
            .stats-table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
            .stats-table th, .stats-table td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #eee; }
            .stats-table th { background: #e9ecef; position: sticky; top: 0; color: #34495e;}
            .stats-table tbody tr:hover { background-color: #e8f4fd !important; }
            .stats-table tbody tr:nth-child(even) { background-color: #f8f9fa; }
            .stats-table .clickable, .clickable-cell { cursor: pointer; } .clickable-cell:hover { text-decoration: underline; color: #2980b9; font-weight: bold; }
            .stats-filter-controls { padding: 8px 12px; background: #f8f9fa; border-bottom: 1px solid #ddd; font-size: 0.85em; color: #555; }
            .stats-filter-controls label { margin-right: 10px; cursor: pointer; } .stats-filter-controls input { vertical-align: middle; margin-right: 4px; }
            .filters { margin-bottom: 15px; display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
            .filter-input, .filter-select, .filter-button { padding: 8px 12px; border: 1px solid #bdc3c7; border-radius: 5px; font-size: 14px; }
            .filter-input { flex-grow: 1; min-width: 200px; }
            .filter-button { background-color: #e74c3c; color: white; cursor: pointer; border:none;} .filter-button:hover { background-color: #c0392b; }
            .filter-status { flex-basis: 100%; margin-top: 5px; color: #2c3e50; font-size: 0.9em; background-color: #eaf2f8; padding: 8px 12px; border-radius: 5px; border-left: 4px solid #3498db; word-break: break-word;}
            .table-container { overflow-x: auto; border: 1px solid #ddd; border-radius: 8px; }
            table#vulnTable { width: 100%; border-collapse: collapse; background: white; }
            #vulnTable th { background: #34495e; color: white; padding: 10px; text-align: left; font-weight: 600; position: sticky; top: 0; z-index: 10; font-size: 0.9em; }
            #vulnTable td { padding: 8px 10px; border-bottom: 1px solid #ecf0f1; vertical-align: top; font-size: 0.85em; }
            #vulnTable tbody tr:hover { background-color: #f0faff; }
            #vulnTable tbody tr:nth-child(even) { background-color: #f9f9f9; }
            .severity-critical { background: #e74c3c; } .severity-high { background: #f39c12; } .severity-medium { background: #f1c40f; color: #2c3e50; } .severity-low { background: #27ae60; } .severity-negligible { background: #95a5a6; } .severity-unknown { background: #7f8c8d; }
            .severity-badge { color: white; padding: 3px 8px; border-radius: 12px; font-size: 0.75em; font-weight: bold; display: inline-block; min-width: 65px; text-align:center;}
            .package-name { font-weight: bold; } 
            .version { font-family: monospace; background: #ecf0f1; padding: 1px 5px; border-radius: 3px; font-size: 0.95em;}
            .location { font-family: monospace; color: #555; max-width: 280px; word-break: break-all; line-height: 1.3;}
            .description { max-width: 350px; line-height: 1.4; word-wrap: break-word; color: #333;}
            .type-badge { background: #a569bd; color: white; padding: 2px 6px; border-radius: 3px; font-size: 0.7em; font-weight:normal;}
            .footer { text-align: center; color: #7f8c8d; margin-top: 30px; padding-top: 15px; border-top: 1px solid #ecf0f1; font-size: 0.8em; }
            .count-cell { text-align: right; padding-right: 15px !important; font-family: monospace;}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔍 ${scanTool} Security Report</h1>
            <div class="summary">${buildSummaryCards(stats)}</div>
            
            <h2>📊 Vulnerability Statistics</h2>
            <div class="stats-layout">
                <details open>
                    <summary>By Location (${stats.by_location.length})</summary>
                    ${buildStatsTableWithFilter(stats.by_location, 'Location Path', 'location', 'locationStatsTable', 'locationFilterControls')}
                </details>
                <details open>
                    <summary>By Package (${stats.by_package.length})</summary>
                    ${buildStatsTableWithFilter(stats.by_package, 'Package Name', 'package', 'packageStatsTable', 'packageFilterControls')}
                </details>
                <details open class="stats-full-width">
                    <summary>By Type (${stats.by_type.length})</summary>
                    <div class="stats-table-wrapper"><table id="typeStatsTable" class="stats-table">${buildTypeStatsTable(stats.by_type)}</table></div>
                </details>
            </div>
            
            <h2>📋 Vulnerability Details (<span id="vulnCount"></span>)</h2>
            <div class="filters">
                <input type="text" class="filter-input" id="searchInput" placeholder="🔍 Search CVE, Package, Location, Description...">
                <select class="filter-select" id="severityFilter"><option value="">All Severities</option>${severityOptions}</select>
                <button class="filter-button" id="clearFiltersBtn">Clear All Filters</button>
                <div class="filter-status" id="filterStatus" style="display: none;"></div>
            </div>
            
            <div class="table-container"><table id="vulnTable"><thead><tr><th>CVE ID</th><th>Package</th><th>Version</th><th>Severity</th><th>Fixed</th><th>Type</th><th>Location</th><th>Description</th></tr></thead><tbody>${tableRows}</tbody></table></div>
             <div style="text-align:center; margin-top: 10px; color: #7f8c8d; font-size: 0.8em;" id="noResults" style="display:none;">No vulnerabilities match the current filters.</div>
            
            <div class="footer"><p>📊 Report generated on ${timestamp} by ${scanTool}</p></div>
        </div>
        <script>
            const currentFilters = { search: '', severity: '', location: '', package: '', type: '' };
            const UI = {
                searchInput: document.getElementById('searchInput'),
                severityFilter: document.getElementById('severityFilter'),
                vulnTableRows: document.getElementById('vulnTable').tBodies[0].rows,
                filterStatus: document.getElementById('filterStatus'),
                vulnCount: document.getElementById('vulnCount'),
                clearFiltersBtn: document.getElementById('clearFiltersBtn'),
                noResultsMsg: document.getElementById('noResults'),
            };
            function getSeverityOrder(s) { return {'CRITICAL':1,'HIGH':2,'MEDIUM':3,'LOW':4,'NEGLIGIBLE':5,'UNKNOWN':6}[s.toUpperCase()] || 9; }
            function htmlEscape(str) { return String(str).replace(/&/g, '&').replace(/</g, '<').replace(/>/g, '>').replace(/"/g, '"'); }
            function updateFilterStatus() {
                const parts = [];
                if (currentFilters.search) parts.push(\`Search: <strong>\${htmlEscape(currentFilters.search)}</strong>\`);
                if (currentFilters.severity) parts.push(\`Severity: <strong>\${currentFilters.severity}</strong>\`);
                if (currentFilters.location) parts.push(\`Location: <strong>\${htmlEscape(currentFilters.location)}</strong>\`);
                if (currentFilters.package) parts.push(\`Package: <strong>\${htmlEscape(currentFilters.package)}</strong>\`);
                if (currentFilters.type) parts.push(\`Type: <strong>\${htmlEscape(currentFilters.type)}</strong>\`);
                if (parts.length > 0) {
                    UI.filterStatus.innerHTML = \`<strong>Active Filters:</strong> \${parts.join('  |  ')}\`;
                    UI.filterStatus.style.display = 'block';
                } else { UI.filterStatus.style.display = 'none'; }
            }
            function applyFilters() {
                let visibleCount = 0;
                currentFilters.search = UI.searchInput.value; 
                currentFilters.severity = UI.severityFilter.value;
                const searchLower = currentFilters.search.toLowerCase();
                const severityUpper = currentFilters.severity.toUpperCase();
                for (const row of UI.vulnTableRows) {
                    const rowData = {
                       cve: row.cells[0].textContent, pkg: row.cells[1].textContent,
                       sev: row.cells[3].textContent.trim().toUpperCase(),
                       type: row.dataset.type, loc: row.dataset.location, desc: row.cells[7].textContent
                    };
                    const matchSearch = !searchLower || rowData.cve.toLowerCase().includes(searchLower) || rowData.pkg.toLowerCase().includes(searchLower) || rowData.loc.toLowerCase().includes(searchLower) || rowData.desc.toLowerCase().includes(searchLower);
                    const matchSeverity = !severityUpper || rowData.sev === severityUpper;
                    const matchLocation = !currentFilters.location || rowData.loc === currentFilters.location; 
                    const matchPackage = !currentFilters.package || rowData.pkg === currentFilters.package; 
                    const matchType = !currentFilters.type || rowData.type === currentFilters.type;
                    if (matchSearch && matchSeverity && matchLocation && matchPackage && matchType) {
                        row.style.display = ''; visibleCount++;
                    } else { row.style.display = 'none'; }
                }
                UI.vulnCount.textContent = \`\${visibleCount} / ${totalVulns}\`;
                UI.noResultsMsg.style.display = visibleCount === 0 && ${totalVulns} > 0 ? 'block' : 'none';
                updateFilterStatus();
            }
            function filterStatsTable(tableId, controlsId) {
                const table = document.getElementById(tableId); if (!table) return;
                const checkboxes = document.querySelectorAll(\`#\${controlsId} input:checked\`);
                const severitiesToShow = Array.from(checkboxes).map(cb => cb.value);
                for (const row of table.tBodies[0].rows) {
                    if (severitiesToShow.length === 0) { row.style.display = ''; } 
                    else {
                        const shouldShow = severitiesToShow.some(sev => parseInt(row.dataset[sev + 'Count'] || 0) > 0);
                        row.style.display = shouldShow ? '' : 'none';
                    }
                }
            }
            function setDimensionalFilter(type, value) {
                currentFilters.location = ''; currentFilters.package = ''; currentFilters.type = '';
                currentFilters[type] = value; applyFilters(); 
            }
           function setTypedFilter(type, severity) {
                currentFilters.location = ''; currentFilters.package = ''; currentFilters.type = type;
                UI.severityFilter.value = severity; applyFilters(); 
            }
            function setSeverityFilter(severity) { UI.severityFilter.value = severity; applyFilters(); }
            function clearFilters() {
                Object.keys(currentFilters).forEach(k => currentFilters[k] = '');
                UI.searchInput.value = ''; UI.severityFilter.value = '';
                document.querySelectorAll('.stats-filter-controls input:checked').forEach(cb => cb.checked = false);
                filterStatsTable('locationStatsTable', 'locationFilterControls');
                filterStatsTable('packageStatsTable', 'packageFilterControls');
                applyFilters();
            }
            document.addEventListener('DOMContentLoaded', () => {
                const tbody = document.getElementById('vulnTable').tBodies[0];
                 if (tbody) { Array.from(tbody.rows).sort((a, b) => getSeverityOrder(a.cells[3].textContent.trim()) - getSeverityOrder(b.cells[3].textContent.trim())).forEach(row => tbody.appendChild(row)); }
                UI.searchInput.addEventListener('input', applyFilters);
                UI.severityFilter.addEventListener('change', applyFilters);
                UI.clearFiltersBtn.addEventListener('click', clearFilters);
                document.querySelectorAll('#locationFilterControls input').forEach(cb => cb.addEventListener('change', () => filterStatsTable('locationStatsTable', 'locationFilterControls')));
                document.querySelectorAll('#packageFilterControls input').forEach(cb => cb.addEventListener('change', () => filterStatsTable('packageStatsTable', 'packageFilterControls')));
                applyFilters();
                window.setDimensionalFilter = setDimensionalFilter; window.setTypedFilter = setTypedFilter; window.setSeverityFilter = setSeverityFilter;
            });
        </script>
    </body>
    </html>
    `;
}

// 导出 Hono app，让 Cloudflare Workers 知道如何运行它
export default app;
