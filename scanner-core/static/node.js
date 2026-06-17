// Node detail page JavaScript
// Handles display of node details, vulnerabilities, and SBOM tables

// State management for vulnerabilities table
let vulnState = {
    page: 1,
    pageSize: 100,
    sortBy: 'severity',
    sortOrder: 'ASC',
    severity: [],
    fixStatus: [],
    packageType: [],
    allData: [] // Store all vulnerability data for client-side operations
};

// State management for SBOM table
let sbomState = {
    page: 1,
    pageSize: 100,
    sortBy: 'name',
    sortOrder: 'ASC',
    type: [],
    allData: [] // Store all package data for client-side operations
};

// Global state
let currentNodeName = '';

// Get node name from URL
function getNodeName() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('name');
}

// Initialize page
async function initPage() {
    currentNodeName = getNodeName();

    if (!currentNodeName) {
        alert('No node name provided');
        return;
    }

    await loadConfig();
    pageConfig.currentPageUrl = 'nodes.html';
    renderTopBarNav();
    await loadNodeDetails(currentNodeName);
    await loadFilterOptions();
    loadVulnerabilitiesTable(currentNodeName);
    renderVersionFooter();

    // Set export links
    updateVulnExportLinks();
    updateSBOMExportLinks();
}

// Global onFilterChange function called by CustomMultiSelect
function onFilterChange() {
    const cvesVisible = document.getElementById('cvesSection').style.display !== 'none';
    if (cvesVisible) {
        onVulnFilterChange();
    } else {
        onSBOMFilterChange();
    }
}

// Load node details
async function loadNodeDetails(nodeName) {
    try {
        const response = await fetch(`/api/nodes/${encodeURIComponent(nodeName)}`);
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Server response:', response.status, errorText);
            throw new Error(`Server returned ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        console.log('Node details loaded:', data);

        document.getElementById('node_name').textContent = data.name || '';
        document.getElementById('hostname').textContent = data.hostname || data.name || '';

        // Populate the page heading with the node name as <h1>.
        const headingContainer = document.getElementById('pageHeading');
        if (headingContainer) {
            const name = data.name || 'Node Summary';
            headingContainer.innerHTML = `<h1>${escapeHtml(name)}</h1>`;
            document.title = name + (appConfig && appConfig.clusterName ? ' - ' + appConfig.clusterName : '');
        }
        document.getElementById('os_release').textContent = data.os_release || 'Unknown';
        document.getElementById('kernel_version').textContent = data.kernel_version || '-';
        document.getElementById('architecture').textContent = data.architecture || '-';
        document.getElementById('scan_status').textContent = data.status || 'Unknown';
        document.getElementById('vulns_scanned_at').textContent = formatTimestamp(data.vulns_scanned_at) || '-';
        document.getElementById('grype_db_built').textContent = formatTimestamp(data.grype_db_built) || '-';

    } catch (error) {
        console.error('Error loading node details:', error);
        alert('Error loading node details: ' + error.message);
    }
}

// Load filter options (shared for both tabs)
async function loadFilterOptions() {
    try {
        // Severity filter - standard values
        const severitySelect = document.getElementById('severityFilter');
        const severities = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];
        severitySelect.innerHTML = severities.map(sev =>
            `<option value="${escapeHtml(sev)}">${escapeHtml(sev)}</option>`
        ).join('');

        // Fix status filter
        const fixStatusSelect = document.getElementById('fixStatusFilter');
        const fixStatuses = ['fixed', 'not-fixed', 'wont-fix', 'unknown'];
        fixStatusSelect.innerHTML = fixStatuses.map(status =>
            `<option value="${escapeHtml(status)}">${escapeHtml(status)}</option>`
        ).join('');

        // Package type filter - load from node filter options
        const packageTypeSelect = document.getElementById('packageTypeFilter');
        try {
            const response = await fetch('/api/node-filter-options');
            if (response.ok) {
                const data = await response.json();
                const packageTypes = data.packageTypes || ['deb', 'rpm', 'apk', 'python', 'npm', 'go'];
                packageTypeSelect.innerHTML = packageTypes.map(type =>
                    `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`
                ).join('');
            }
        } catch (e) {
            // Fallback to common types
            const packageTypes = ['deb', 'rpm', 'apk', 'python', 'npm', 'go'];
            packageTypeSelect.innerHTML = packageTypes.map(type =>
                `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`
            ).join('');
        }

        // Initialize multiselects using shared.js multiselectInstances
        multiselectInstances['severityFilter'] = new CustomMultiSelect(severitySelect, 'All severities');
        multiselectInstances['fixStatusFilter'] = new CustomMultiSelect(fixStatusSelect, 'All statuses');
        multiselectInstances['packageTypeFilter'] = new CustomMultiSelect(packageTypeSelect, 'All types');

    } catch (error) {
        console.error('Error loading filter options:', error);
    }
}

// Severity sort order for proper sorting
const severityOrder = {
    'Critical': 0,
    'High': 1,
    'Medium': 2,
    'Low': 3,
    'Negligible': 4,
    'Unknown': 5
};

// Load vulnerabilities table
async function loadVulnerabilitiesTable(nodeName) {
    const tableBody = document.querySelector('#cvesTable tbody');

    try {
        // Fetch all vulnerabilities (API doesn't support pagination yet)
        const response = await fetch(`/api/nodes/${encodeURIComponent(nodeName)}/vulnerabilities`);
        if (!response.ok) throw new Error('Failed to load vulnerabilities');

        let data = await response.json();

        // Handle null, array, and paginated response
        if (data === null) {
            vulnState.allData = [];
        } else {
            vulnState.allData = Array.isArray(data) ? data : (data.vulnerabilities || []);
        }

        // Enrich with package info if needed (also populates sbomState.allData)
        await enrichVulnerabilitiesWithPackages(nodeName);

        // Compute stats from loaded data
        computeAndPopulateStats();

        // Apply filters and render
        renderVulnerabilitiesTable();

    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', 'Error loading vulnerabilities: ' + error.message);
        cell.colSpan = 8;
        cell.style.color = 'red';
        tableBody.appendChild(row);
    }
}

// Enrich vulnerabilities with package info (also populates sbomState.allData)
async function enrichVulnerabilitiesWithPackages(nodeName) {
    try {
        const response = await fetch(`/api/nodes/${encodeURIComponent(nodeName)}/packages`);
        if (!response.ok) return;

        const packages = await response.json();
        if (packages === null) return; // No packages yet

        const pkgArray = Array.isArray(packages) ? packages : (packages.packages || []);

        // Also populate sbomState.allData to avoid a duplicate fetch when SBOM tab opens
        sbomState.allData = pkgArray;

        const packageMap = {};

        // Build package lookup by ID
        pkgArray.forEach(pkg => {
            packageMap[pkg.id] = pkg;
        });

        // Enrich vulnerabilities with package info
        vulnState.allData.forEach(vuln => {
            const pkg = packageMap[vuln.package_id];
            if (pkg) {
                vuln.package_name = pkg.name;
                vuln.package_version = pkg.version;
                vuln.package_type = pkg.type;
            }
        });

    } catch (error) {
        console.error('Error enriching vulnerabilities with packages:', error);
    }
}

// Render vulnerabilities table with current filters, sort, and pagination
function renderVulnerabilitiesTable() {
    const tableBody = document.querySelector('#cvesTable tbody');
    tableBody.innerHTML = '';

    // Handle empty data
    if (vulnState.allData.length === 0) {
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', 'No vulnerability data available. Node may not have been scanned yet.');
        cell.colSpan = 8;
        cell.style.color = '#666';
        tableBody.appendChild(row);
        renderVulnPagination(1, 1, 0);
        return;
    }

    // Filter data
    let filtered = vulnState.allData.filter(vuln => {
        if (vulnState.severity.length && !vulnState.severity.includes(vuln.severity)) return false;
        if (vulnState.fixStatus.length && !vulnState.fixStatus.includes(vuln.fix_status)) return false;
        if (vulnState.packageType.length && !vulnState.packageType.includes(vuln.package_type)) return false;
        return true;
    });

    // Sort data
    filtered.sort((a, b) => {
        let aVal = a[vulnState.sortBy];
        let bVal = b[vulnState.sortBy];

        // Special handling for severity
        if (vulnState.sortBy === 'severity') {
            aVal = severityOrder[aVal] !== undefined ? severityOrder[aVal] : 999;
            bVal = severityOrder[bVal] !== undefined ? severityOrder[bVal] : 999;
        }

        // Handle string comparison
        if (typeof aVal === 'string') {
            aVal = (aVal || '').toLowerCase();
            bVal = (bVal || '').toLowerCase();
        }

        if (aVal < bVal) return vulnState.sortOrder === 'ASC' ? -1 : 1;
        if (aVal > bVal) return vulnState.sortOrder === 'ASC' ? 1 : -1;
        return 0;
    });

    // Paginate
    const totalCount = filtered.length;
    const totalPages = Math.ceil(totalCount / vulnState.pageSize) || 1;
    const startIndex = (vulnState.page - 1) * vulnState.pageSize;
    const pageData = filtered.slice(startIndex, startIndex + vulnState.pageSize);

    // Render rows
    pageData.forEach(vuln => {
        const row = document.createElement('tr');
        row.classList.add('clickable-row');
        row.style.cursor = 'pointer';

        // Make row clickable to show details
        row.onclick = function() {
            showVulnerabilityDetails(vuln.id, vuln.cve_id);
        };

        // Severity
        addCellToRow(row, 'left', vuln.severity || '');

        // CVE ID
        addCellToRow(row, 'left', vuln.cve_id || '');

        // Package name
        addCellToRow(row, 'left', vuln.package_name || '');

        // Package version
        addCellToRow(row, 'left', vuln.package_version || '');

        // Fix version
        addCellToRow(row, 'left', vuln.fix_version || '');

        // Fix status
        addCellToRow(row, 'left', vuln.fix_status || '');

        // Package type
        addCellToRow(row, 'left', vuln.package_type || '');

        // Risk
        addCellToRow(row, 'right', vuln.risk ? formatRiskNumber(vuln.risk) : '-');

        // Exploits (known_exploited) - count from CISA KEV catalog
        addCellToRow(row, 'right', formatNumber(vuln.known_exploited || 0));

        // Count (number of instances of this vulnerability)
        addCellToRow(row, 'right', formatNumber(vuln.count || 1));

        tableBody.appendChild(row);
    });

    renderVulnPagination(vulnState.page, totalPages, totalCount);
    updateVulnSortIndicators();
}

// Load SBOM table
async function loadSBOMTable(nodeName) {
    const tableBody = document.querySelector('#sbomTable tbody');

    try {
        const response = await fetch(`/api/nodes/${encodeURIComponent(nodeName)}/packages`);
        if (!response.ok) throw new Error('Failed to load packages');

        let data = await response.json();

        // Handle null, array, and paginated response
        if (data === null) {
            sbomState.allData = [];
        } else {
            sbomState.allData = Array.isArray(data) ? data : (data.packages || []);
        }

        // Apply filters and render
        renderSBOMTable();

    } catch (error) {
        console.error('Error loading packages:', error);
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', 'Error loading packages: ' + error.message);
        cell.colSpan = 4;
        cell.style.color = 'red';
        tableBody.appendChild(row);
    }
}

// Render SBOM table with current filters, sort, and pagination
function renderSBOMTable() {
    const tableBody = document.querySelector('#sbomTable tbody');
    tableBody.innerHTML = '';

    // Handle empty data
    if (sbomState.allData.length === 0) {
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', 'No package data available. Node may not have been scanned yet.');
        cell.colSpan = 4;
        cell.style.color = '#666';
        tableBody.appendChild(row);
        renderSBOMPagination(1, 1, 0);
        return;
    }

    // Filter data
    let filtered = sbomState.allData.filter(pkg => {
        if (sbomState.type.length && !sbomState.type.includes(pkg.type)) return false;
        return true;
    });

    // Sort data
    filtered.sort((a, b) => {
        let aVal = a[sbomState.sortBy];
        let bVal = b[sbomState.sortBy];

        if (typeof aVal === 'string') {
            aVal = (aVal || '').toLowerCase();
            bVal = (bVal || '').toLowerCase();
        }

        if (aVal < bVal) return sbomState.sortOrder === 'ASC' ? -1 : 1;
        if (aVal > bVal) return sbomState.sortOrder === 'ASC' ? 1 : -1;
        return 0;
    });

    // Paginate
    const totalCount = filtered.length;
    const totalPages = Math.ceil(totalCount / sbomState.pageSize) || 1;
    const startIndex = (sbomState.page - 1) * sbomState.pageSize;
    const pageData = filtered.slice(startIndex, startIndex + sbomState.pageSize);

    // Render rows
    pageData.forEach(pkg => {
        const row = document.createElement('tr');
        row.classList.add('clickable-row');
        row.style.cursor = 'pointer';

        // Make row clickable to show details
        row.onclick = function() {
            showPackageDetails(pkg.id, pkg.name);
        };

        // Name
        addCellToRow(row, 'left', pkg.name || '');

        // Version
        addCellToRow(row, 'left', pkg.version || '');

        // Type
        addCellToRow(row, 'left', pkg.type || '');

        // Count (vulnerability count)
        addCellToRow(row, 'right', formatNumber(pkg.count || 0));

        tableBody.appendChild(row);
    });

    renderSBOMPagination(sbomState.page, totalPages, totalCount);
    updateSBOMSortIndicators();
}

// Tab switching
const CVES_TAB = { section: 'cvesSection', header: 'cvesHeader' };
const SBOM_TAB = { section: 'sbomSection', header: 'sbomHeader' };

function showVulnerabilityTable() { showTab(CVES_TAB, SBOM_TAB, onVulnFilterChange); }
function showSBOMTable()          { showTab(SBOM_TAB, CVES_TAB, onSBOMFilterChange); }

// Filter change handlers
function onVulnFilterChange() {
    vulnState.page = 1;
    vulnState.severity = multiselectInstances['severityFilter'] ? multiselectInstances['severityFilter'].getSelected() : [];
    vulnState.fixStatus = multiselectInstances['fixStatusFilter'] ? multiselectInstances['fixStatusFilter'].getSelected() : [];
    vulnState.packageType = multiselectInstances['packageTypeFilter'] ? multiselectInstances['packageTypeFilter'].getSelected() : [];
    renderVulnerabilitiesTable();
    updateVulnExportLinks();
    computeAndPopulateStats();
}

function onSBOMFilterChange() {
    sbomState.page = 1;
    sbomState.type = multiselectInstances['packageTypeFilter'] ? multiselectInstances['packageTypeFilter'].getSelected() : [];
    vulnState.packageType = sbomState.type; // sync for stats
    if (sbomState.allData.length === 0) {
        loadSBOMTable(currentNodeName);
    } else {
        renderSBOMTable();
    }
    updateSBOMExportLinks();
    computeAndPopulateStats();
}

// Populate stats fields from data object
function populateStats(data) {
    document.getElementById('total_risk').textContent = formatRiskNumber(data.total_risk);
    document.getElementById('total_cves').textContent = formatNumber(data.total_cves);
    document.getElementById('unique_cves').textContent = formatNumber(data.unique_cves);
    document.getElementById('total_exploits').textContent = formatNumber(data.total_exploits);
    document.getElementById('unique_exploits').textContent = formatNumber(data.unique_exploits);
    document.getElementById('total_packages').textContent = formatNumber(data.total_packages);
    document.getElementById('unique_packages').textContent = formatNumber(data.unique_packages);
    document.getElementById('cves_critical').textContent = formatNumber(data.cves_critical);
    document.getElementById('cves_high').textContent = formatNumber(data.cves_high);
    document.getElementById('cves_medium').textContent = formatNumber(data.cves_medium);
    document.getElementById('cves_low').textContent = formatNumber(data.cves_low);
    document.getElementById('cves_negligible').textContent = formatNumber(data.cves_negligible);
    document.getElementById('cves_unknown').textContent = formatNumber(data.cves_unknown);
}

// Compute stats client-side from filtered data
function computeAndPopulateStats() {
    // Filter vulns with current state
    const filteredVulns = vulnState.allData.filter(vuln => {
        if (vulnState.severity.length && !vulnState.severity.includes(vuln.severity)) return false;
        if (vulnState.fixStatus.length && !vulnState.fixStatus.includes(vuln.fix_status)) return false;
        if (vulnState.packageType.length && !vulnState.packageType.includes(vuln.package_type)) return false;
        return true;
    });

    let totalRisk = 0, totalCves = 0, totalExploits = 0;
    const uniqueCveIds = new Set();
    const uniqueExploitIds = new Set();
    const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Negligible: 0, Unknown: 0 };

    filteredVulns.forEach(vuln => {
        const count = vuln.count || 1;
        totalRisk += (vuln.risk || 0) * count;
        totalCves += count;
        uniqueCveIds.add(vuln.cve_id);
        totalExploits += (vuln.known_exploited || 0) * count;
        if ((vuln.known_exploited || 0) > 0) {
            uniqueExploitIds.add(vuln.cve_id);
        }
        const sev = vuln.severity || 'Unknown';
        if (sevCounts[sev] !== undefined) {
            sevCounts[sev] += count;
        } else {
            sevCounts['Unknown'] += count;
        }
    });

    // Filter packages by type
    const filteredPkgs = sbomState.allData.filter(pkg => {
        if (vulnState.packageType.length && !vulnState.packageType.includes(pkg.type)) return false;
        return true;
    });

    populateStats({
        total_risk: totalRisk,
        total_cves: totalCves,
        unique_cves: uniqueCveIds.size,
        total_exploits: totalExploits,
        unique_exploits: uniqueExploitIds.size,
        total_packages: filteredPkgs.reduce((sum, pkg) => sum + (pkg.count || 1), 0),
        unique_packages: filteredPkgs.length,
        cves_critical: sevCounts.Critical,
        cves_high: sevCounts.High,
        cves_medium: sevCounts.Medium,
        cves_low: sevCounts.Low,
        cves_negligible: sevCounts.Negligible,
        cves_unknown: sevCounts.Unknown,
    });
}

// Sorting handlers
function sortVulnByColumn(field) {
    if (vulnState.sortBy === field) {
        vulnState.sortOrder = vulnState.sortOrder === 'ASC' ? 'DESC' : 'ASC';
    } else {
        vulnState.sortBy = field;
        vulnState.sortOrder = 'ASC';
    }
    renderVulnerabilitiesTable();
}

function sortSBOMByColumn(field) {
    if (sbomState.sortBy === field) {
        sbomState.sortOrder = sbomState.sortOrder === 'ASC' ? 'DESC' : 'ASC';
    } else {
        sbomState.sortBy = field;
        sbomState.sortOrder = 'ASC';
    }
    renderSBOMTable();
}

// Update sort indicators
function updateVulnSortIndicators() {
    document.querySelectorAll('#cvesTable th.sortable').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.sortField === vulnState.sortBy) {
            th.classList.add(vulnState.sortOrder === 'ASC' ? 'sort-asc' : 'sort-desc');
        }
    });
}

function updateSBOMSortIndicators() {
    document.querySelectorAll('#sbomTable th.sortable').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.sortField === sbomState.sortBy) {
            th.classList.add(sbomState.sortOrder === 'ASC' ? 'sort-asc' : 'sort-desc');
        }
    });
}

// Pagination handlers
function goToVulnPage(page) {
    if (page < 1) return;
    vulnState.page = page;
    renderVulnerabilitiesTable();
}

function prevVulnPage() {
    if (vulnState.page > 1) {
        vulnState.page--;
        renderVulnerabilitiesTable();
    }
}

function nextVulnPage(totalPages) {
    if (vulnState.page < totalPages) {
        vulnState.page++;
        renderVulnerabilitiesTable();
    }
}

function goToSBOMPage(page) {
    if (page < 1) return;
    sbomState.page = page;
    renderSBOMTable();
}

function prevSBOMPage() {
    if (sbomState.page > 1) {
        sbomState.page--;
        renderSBOMTable();
    }
}

function nextSBOMPage(totalPages) {
    if (sbomState.page < totalPages) {
        sbomState.page++;
        renderSBOMTable();
    }
}

// Render pagination
function renderVulnPagination(currentPage, totalPages, totalCount) {
    const paginationDiv = document.getElementById('vulnPagination');
    if (!paginationDiv) return;

    if (totalPages <= 1) {
        paginationDiv.innerHTML = `<span style="color: #666;">Showing ${totalCount} vulnerabilities</span>`;
        return;
    }

    let html = '<div style="display: flex; justify-content: center; align-items: center; gap: 10px;">';

    html += `<button onclick="prevVulnPage()" ${currentPage === 1 ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === 1 ? 'default' : 'pointer'};">Previous</button>`;

    html += '<div style="display: flex; gap: 5px;">';

    if (currentPage > 3) {
        html += `<button onclick="goToVulnPage(1)" style="padding: 5px 10px; cursor: pointer;">1</button>`;
        if (currentPage > 4) {
            html += `<span style="padding: 5px;">...</span>`;
        }
    }

    for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
        if (i === currentPage) {
            html += `<button style="padding: 5px 10px; font-weight: bold; background: lightgrey;">${i}</button>`;
        } else {
            html += `<button onclick="goToVulnPage(${i})" style="padding: 5px 10px; cursor: pointer;">${i}</button>`;
        }
    }

    if (currentPage < totalPages - 2) {
        if (currentPage < totalPages - 3) {
            html += `<span style="padding: 5px;">...</span>`;
        }
        html += `<button onclick="goToVulnPage(${totalPages})" style="padding: 5px 10px; cursor: pointer;">${totalPages}</button>`;
    }

    html += '</div>';

    html += `<button onclick="nextVulnPage(${totalPages})" ${currentPage === totalPages ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === totalPages ? 'default' : 'pointer'};">Next</button>`;

    const startItem = (currentPage - 1) * vulnState.pageSize + 1;
    const endItem = Math.min(currentPage * vulnState.pageSize, totalCount);
    html += `<span style="margin-left: 20px; color: #666;">Showing ${startItem}-${endItem} of ${totalCount}</span>`;

    html += '</div>';

    paginationDiv.innerHTML = html;
}

function renderSBOMPagination(currentPage, totalPages, totalCount) {
    const paginationDiv = document.getElementById('sbomPagination');
    if (!paginationDiv) return;

    if (totalPages <= 1) {
        paginationDiv.innerHTML = `<span style="color: #666;">Showing ${totalCount} packages</span>`;
        return;
    }

    let html = '<div style="display: flex; justify-content: center; align-items: center; gap: 10px;">';

    html += `<button onclick="prevSBOMPage()" ${currentPage === 1 ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === 1 ? 'default' : 'pointer'};">Previous</button>`;

    html += '<div style="display: flex; gap: 5px;">';

    if (currentPage > 3) {
        html += `<button onclick="goToSBOMPage(1)" style="padding: 5px 10px; cursor: pointer;">1</button>`;
        if (currentPage > 4) {
            html += `<span style="padding: 5px;">...</span>`;
        }
    }

    for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
        if (i === currentPage) {
            html += `<button style="padding: 5px 10px; font-weight: bold; background: lightgrey;">${i}</button>`;
        } else {
            html += `<button onclick="goToSBOMPage(${i})" style="padding: 5px 10px; cursor: pointer;">${i}</button>`;
        }
    }

    if (currentPage < totalPages - 2) {
        if (currentPage < totalPages - 3) {
            html += `<span style="padding: 5px;">...</span>`;
        }
        html += `<button onclick="goToSBOMPage(${totalPages})" style="padding: 5px 10px; cursor: pointer;">${totalPages}</button>`;
    }

    html += '</div>';

    html += `<button onclick="nextSBOMPage(${totalPages})" ${currentPage === totalPages ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === totalPages ? 'default' : 'pointer'};">Next</button>`;

    const startItem = (currentPage - 1) * sbomState.pageSize + 1;
    const endItem = Math.min(currentPage * sbomState.pageSize, totalCount);
    html += `<span style="margin-left: 20px; color: #666;">Showing ${startItem}-${endItem} of ${totalCount}</span>`;

    html += '</div>';

    paginationDiv.innerHTML = html;
}

// Update export links
function updateVulnExportLinks() {
    const baseUrl = `/api/nodes/${encodeURIComponent(currentNodeName)}/vulnerabilities`;
    document.getElementById('cvecsvlink').href = `${baseUrl}?format=csv`;
    document.getElementById('cvejsonlink').href = `${baseUrl}?format=json`;
}

function updateSBOMExportLinks() {
    const baseUrl = `/api/nodes/${encodeURIComponent(currentNodeName)}/packages`;
    document.getElementById('sbomcsvlink').href = `${baseUrl}?format=csv`;
    document.getElementById('sbomjsonlink').href = `${baseUrl}?format=json`;
}

// Modal functions for displaying JSON details
function showDetailsModal(title, content) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalContent').textContent = content;
    document.getElementById('detailsModal').style.display = 'block';
}

function closeDetailsModal() {
    document.getElementById('detailsModal').style.display = 'none';
}

// Close modal when clicking outside of it
window.onclick = function(event) {
    const modal = document.getElementById('detailsModal');
    if (event.target === modal) {
        closeDetailsModal();
    }
};

// Fetch and display vulnerability details
async function showVulnerabilityDetails(vulnerabilityId, vulnerabilityCVE) {
    if (!vulnerabilityId) {
        showDetailsModal('Error', 'No vulnerability ID available');
        return;
    }

    const url = `/api/node-vulnerabilities/${vulnerabilityId}/details`;

    try {
        const response = await fetch(url);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        const prettyJson = JSON.stringify(data, null, 2);
        showDetailsModal(`Vulnerability Details: ${vulnerabilityCVE || vulnerabilityId}`, prettyJson);
    } catch (error) {
        console.error('Error fetching vulnerability details:', error);
        showDetailsModal('Error', `Failed to load vulnerability details:\n\n${error.message}`);
    }
}

// Fetch and display package details
async function showPackageDetails(packageId, packageName) {
    if (!packageId) {
        showDetailsModal('Error', 'No package ID available');
        return;
    }

    const url = `/api/node-packages/${packageId}/details`;

    try {
        const response = await fetch(url);
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        const prettyJson = JSON.stringify(data, null, 2);
        showDetailsModal(`Package Details: ${packageName || packageId}`, prettyJson);
    } catch (error) {
        console.error('Error fetching package details:', error);
        showDetailsModal('Error', `Failed to load package details:\n\n${error.message}`);
    }
}

// DOM ready
document.addEventListener('DOMContentLoaded', initPage);
