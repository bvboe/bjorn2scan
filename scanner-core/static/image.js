// Image detail page JavaScript
// Handles display of image details, vulnerabilities, and SBOM tables

// State management for vulnerabilities table
let vulnState = {
    page: 1,
    pageSize: 100,
    sortBy: 'vulnerability_severity',
    sortOrder: 'ASC',
    severity: [],
    fixStatus: [],
    packageType: []
};

// State management for SBOM table
let sbomState = {
    page: 1,
    pageSize: 100,
    sortBy: 'name',
    sortOrder: 'ASC',
    type: []
};

// Global state
let currentImageId = '';

// Get image ID from URL
function getImageId() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('imageid');
}

// Initialize page
async function initPage() {
    currentImageId = getImageId();

    if (!currentImageId) {
        alert('No image ID provided');
        return;
    }

    await loadConfig();
    pageConfig.currentPageUrl = 'images.html';
    renderTopBarNav();
    await loadImageDetails(currentImageId);
    await loadFilterOptions();
    loadVulnerabilitiesTable(currentImageId);
    renderVersionFooter();

    // Set export links
    updateVulnExportLinks();
    updateSBOMExportLinks();
}

// Dispatches filter changes to the active tab
function onFilterChange() {
    const cvesVisible = document.getElementById('cvesSection').style.display !== 'none';
    if (cvesVisible) {
        onVulnFilterChange();
    } else {
        onSBOMFilterChange();
    }
}

// Load image details
async function loadImageDetails(imageid) {
    try {
        const response = await fetch(`/api/images/${encodeURIComponent(imageid)}`);
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Server response:', response.status, errorText);
            throw new Error(`Server returned ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        console.log('Image details loaded:', data);

        document.getElementById('image_id').textContent = data.image_id || '';
        document.getElementById('references').innerHTML = (data.references || []).join('<br>') || 'N/A';

        // Populate the page heading with one <h1> per image reference.
        // Most images have a single reference; multi-tag images get one heading each.
        const headingContainer = document.getElementById('pageHeading');
        if (headingContainer) {
            const refs = data.references || [];
            if (refs.length > 0) {
                headingContainer.innerHTML = refs.map(r => `<h1>${escapeHtml(r)}</h1>`).join('');
                document.title = refs[0] + (appConfig && appConfig.clusterName ? ' - ' + appConfig.clusterName : '');
            } else {
                headingContainer.innerHTML = '<h1>Image Summary</h1>';
            }
        }
        document.getElementById('containers').innerHTML = (data.containers || []).join('<br>') || 'N/A';
        document.getElementById('distro_display_name').textContent = data.distro_display_name || 'Unknown';
        document.getElementById('scan_status').textContent = data.status_description || 'Unknown';
        document.getElementById('vulns_scanned_at').textContent = formatTimestamp(data.vulns_scanned_at) || '-';
        document.getElementById('grype_db_built').textContent = formatTimestamp(data.grype_db_built) || '-';

        populateStats(data);

    } catch (error) {
        console.error('Error loading image details:', error);
        alert('Error loading image details: ' + error.message);
    }
}

// Load filter options (shared across both tabs)
async function loadFilterOptions() {
    try {
        const response = await fetch('/api/filter-options');
        if (!response.ok) throw new Error('Failed to load filter options');

        const data = await response.json();

        const severitySelect = document.getElementById('severityFilter');
        const severities = ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown'];
        severitySelect.innerHTML = severities.map(sev =>
            `<option value="${escapeHtml(sev)}">${escapeHtml(sev)}</option>`
        ).join('');

        const fixStatusSelect = document.getElementById('fixStatusFilter');
        const fixStatuses = data.vulnStatuses || [];
        fixStatusSelect.innerHTML = fixStatuses.map(status =>
            `<option value="${escapeHtml(status)}">${escapeHtml(status)}</option>`
        ).join('');

        const packageTypeSelect = document.getElementById('packageTypeFilter');
        const packageTypes = data.packageTypes || [];
        packageTypeSelect.innerHTML = packageTypes.map(type =>
            `<option value="${escapeHtml(type)}">${escapeHtml(type)}</option>`
        ).join('');

        multiselectInstances['severityFilter'] = new CustomMultiSelect(severitySelect, 'All severities');
        multiselectInstances['fixStatusFilter'] = new CustomMultiSelect(fixStatusSelect, 'All statuses');
        multiselectInstances['packageTypeFilter'] = new CustomMultiSelect(packageTypeSelect, 'All types');

    } catch (error) {
        console.error('Error loading filter options:', error);
    }
}

// Load vulnerabilities table
async function loadVulnerabilitiesTable(imageid) {
    const tableBody = document.querySelector('#cvesTable tbody');

    try {
        const params = new URLSearchParams({
            page: vulnState.page,
            pageSize: vulnState.pageSize,
            sortBy: vulnState.sortBy,
            sortOrder: vulnState.sortOrder
        });

        if (vulnState.severity.length) params.append('severity', vulnState.severity.join(','));
        if (vulnState.fixStatus.length) params.append('fixStatus', vulnState.fixStatus.join(','));
        if (vulnState.packageType.length) params.append('packageType', vulnState.packageType.join(','));

        const response = await fetch(`/api/images/${encodeURIComponent(imageid)}/vulnerabilities?${params}`);
        if (!response.ok) throw new Error('Failed to load vulnerabilities');

        const data = await response.json();
        tableBody.innerHTML = '';

        (data.vulnerabilities || []).forEach(vuln => {
            const row = document.createElement('tr');
            row.classList.add('clickable-row');

            // Make row clickable to show details
            row.style.cursor = 'pointer';
            row.onclick = function() {
                console.log('[Row Click] Vulnerability row clicked');
                console.log('[Row Click] vuln object:', vuln);
                console.log('[Row Click] vuln.id:', vuln.id, 'type:', typeof vuln.id);
                console.log('[Row Click] vuln.vulnerability_id:', vuln.vulnerability_id);
                showVulnerabilityDetails(vuln.id, vuln.vulnerability_id);
            };

            // Severity
            addCellToRow(row, 'left', vuln.vulnerability_severity || '');

            // Vulnerability ID
            addCellToRow(row, 'left', vuln.vulnerability_id || '');

            // Artifact name
            addCellToRow(row, 'left', vuln.artifact_name || '');

            // Artifact version
            addCellToRow(row, 'left', vuln.artifact_version || '');

            // Fix versions
            addCellToRow(row, 'left', vuln.vulnerability_fix_versions || '');

            // Fix state
            addCellToRow(row, 'left', vuln.vulnerability_fix_state || '');

            // Artifact type
            addCellToRow(row, 'left', vuln.artifact_type || '');

            // Risk
            addCellToRow(row, 'right', formatRiskNumber(vuln.vulnerability_risk));

            // Known exploits
            addCellToRow(row, 'right', formatNumber(vuln.vulnerability_known_exploits));

            // Count
            addCellToRow(row, 'right', formatNumber(vuln.vulnerability_count));

            tableBody.appendChild(row);
        });

        renderVulnPagination(data.page || 1, data.totalPages || 1, data.totalCount || 0);

    } catch (error) {
        console.error('Error loading vulnerabilities:', error);
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', '⚠️ Error loading vulnerabilities: ' + error.message);
        cell.colSpan = 10;
        cell.style.color = 'red';
        tableBody.appendChild(row);
    }
}

// Load SBOM table
async function loadSBOMTable(imageid) {
    const tableBody = document.querySelector('#sbomTable tbody');

    try {
        const params = new URLSearchParams({
            page: sbomState.page,
            pageSize: sbomState.pageSize,
            sortBy: sbomState.sortBy,
            sortOrder: sbomState.sortOrder
        });

        if (sbomState.type.length) params.append('type', sbomState.type.join(','));

        const response = await fetch(`/api/images/${encodeURIComponent(imageid)}/packages?${params}`);
        if (!response.ok) throw new Error('Failed to load packages');

        const data = await response.json();
        tableBody.innerHTML = '';

        (data.packages || []).forEach(pkg => {
            const row = document.createElement('tr');
            row.classList.add('clickable-row');

            // Make row clickable to show details
            row.style.cursor = 'pointer';
            row.onclick = function() {
                console.log('[Row Click] Package row clicked');
                console.log('[Row Click] pkg object:', pkg);
                console.log('[Row Click] pkg.id:', pkg.id, 'type:', typeof pkg.id);
                console.log('[Row Click] pkg.name:', pkg.name);
                showPackageDetails(pkg.id, pkg.name);
            };

            // Name
            addCellToRow(row, 'left', pkg.name || '');

            // Version
            addCellToRow(row, 'left', pkg.version || '');

            // Type
            addCellToRow(row, 'left', pkg.type || '');

            // Count
            addCellToRow(row, 'right', formatNumber(pkg.count));

            tableBody.appendChild(row);
        });

        renderSBOMPagination(data.page || 1, data.totalPages || 1, data.totalCount || 0);

    } catch (error) {
        console.error('Error loading packages:', error);
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', '⚠️ Error loading packages: ' + error.message);
        cell.colSpan = 4;
        cell.style.color = 'red';
        tableBody.appendChild(row);
    }
}

// Tab switching
const CVES_TAB = { section: 'cvesSection', header: 'cvesHeader' };
const SBOM_TAB = { section: 'sbomSection', header: 'sbomHeader' };

function showVulnerabilityTable() { showTab(CVES_TAB, SBOM_TAB, onVulnFilterChange); }
function showSBOMTable()          { showTab(SBOM_TAB, CVES_TAB, onSBOMFilterChange); }

// Populate summary stat fields from a data object
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

// Fetch and update summary stats with current filter state
async function loadImageStats() {
    const params = new URLSearchParams();
    if (vulnState.severity.length) params.append('severity', vulnState.severity.join(','));
    if (vulnState.fixStatus.length) params.append('fixStatus', vulnState.fixStatus.join(','));
    if (vulnState.packageType.length) params.append('packageType', vulnState.packageType.join(','));

    try {
        const response = await fetch(`/api/images/${encodeURIComponent(currentImageId)}/stats?${params}`);
        if (!response.ok) throw new Error('Failed to load stats');
        const data = await response.json();
        populateStats(data);
    } catch (error) {
        console.error('Error loading image stats:', error);
    }
}

// Filter change handlers
function onVulnFilterChange() {
    vulnState.page = 1;
    vulnState.severity = multiselectInstances['severityFilter'] ? multiselectInstances['severityFilter'].getSelected() : [];
    vulnState.fixStatus = multiselectInstances['fixStatusFilter'] ? multiselectInstances['fixStatusFilter'].getSelected() : [];
    vulnState.packageType = multiselectInstances['packageTypeFilter'] ? multiselectInstances['packageTypeFilter'].getSelected() : [];
    loadVulnerabilitiesTable(currentImageId);
    updateVulnExportLinks();
    loadImageStats();
}

function onSBOMFilterChange() {
    sbomState.page = 1;
    sbomState.type = multiselectInstances['packageTypeFilter'] ? multiselectInstances['packageTypeFilter'].getSelected() : [];
    vulnState.packageType = sbomState.type; // keep in sync for loadImageStats
    loadSBOMTable(currentImageId);
    updateSBOMExportLinks();
    loadImageStats();
}

// Sorting handlers
function sortVulnByColumn(field) {
    if (vulnState.sortBy === field) {
        vulnState.sortOrder = vulnState.sortOrder === 'ASC' ? 'DESC' : 'ASC';
    } else {
        vulnState.sortBy = field;
        vulnState.sortOrder = 'ASC';
    }
    updateVulnSortIndicators();
    loadVulnerabilitiesTable(currentImageId);
}

function sortSBOMByColumn(field) {
    if (sbomState.sortBy === field) {
        sbomState.sortOrder = sbomState.sortOrder === 'ASC' ? 'DESC' : 'ASC';
    } else {
        sbomState.sortBy = field;
        sbomState.sortOrder = 'ASC';
    }
    updateSBOMSortIndicators();
    loadSBOMTable(currentImageId);
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
    loadVulnerabilitiesTable(currentImageId);
}

function prevVulnPage() {
    if (vulnState.page > 1) {
        vulnState.page--;
        loadVulnerabilitiesTable(currentImageId);
    }
}

function nextVulnPage(totalPages) {
    if (vulnState.page < totalPages) {
        vulnState.page++;
        loadVulnerabilitiesTable(currentImageId);
    }
}

function goToSBOMPage(page) {
    if (page < 1) return;
    sbomState.page = page;
    loadSBOMTable(currentImageId);
}

function prevSBOMPage() {
    if (sbomState.page > 1) {
        sbomState.page--;
        loadSBOMTable(currentImageId);
    }
}

function nextSBOMPage(totalPages) {
    if (sbomState.page < totalPages) {
        sbomState.page++;
        loadSBOMTable(currentImageId);
    }
}

// Render pagination
function renderVulnPagination(currentPage, totalPages, totalCount) {
    const paginationDiv = document.getElementById('vulnPagination');
    if (!paginationDiv) return;

    if (totalPages <= 1) {
        paginationDiv.innerHTML = '';
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
        paginationDiv.innerHTML = '';
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
    const params = new URLSearchParams({
        page: 1,
        pageSize: 10000,
        sortBy: vulnState.sortBy,
        sortOrder: vulnState.sortOrder
    });

    if (vulnState.severity.length) params.append('severity', vulnState.severity.join(','));
    if (vulnState.fixStatus.length) params.append('fixStatus', vulnState.fixStatus.join(','));
    if (vulnState.packageType.length) params.append('packageType', vulnState.packageType.join(','));

    const baseUrl = `/api/images/${encodeURIComponent(currentImageId)}/vulnerabilities`;
    document.getElementById('cvecsvlink').href = `${baseUrl}?${params}&format=csv`;
    document.getElementById('cvejsonlink').href = `${baseUrl}?${params}&format=json`;
}

function updateSBOMExportLinks() {
    const params = new URLSearchParams({
        page: 1,
        pageSize: 10000,
        sortBy: sbomState.sortBy,
        sortOrder: sbomState.sortOrder
    });

    if (sbomState.type.length) params.append('type', sbomState.type.join(','));

    const baseUrl = `/api/images/${encodeURIComponent(currentImageId)}/packages`;
    document.getElementById('sbomcsvlink').href = `${baseUrl}?${params}&format=csv`;
    document.getElementById('sbomjsonlink').href = `${baseUrl}?${params}&format=json`;
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
}

// Fetch and display vulnerability details
async function showVulnerabilityDetails(vulnerabilityId, vulnerabilityCVE) {
    const url = `/api/vulnerabilities/${vulnerabilityId}/details`;
    console.log('[Vulnerability Details] Click handler called');
    console.log('[Vulnerability Details] ID:', vulnerabilityId);
    console.log('[Vulnerability Details] CVE:', vulnerabilityCVE);
    console.log('[Vulnerability Details] Fetching URL:', url);

    try {
        const response = await fetch(url);
        console.log('[Vulnerability Details] Response status:', response.status);
        console.log('[Vulnerability Details] Response OK:', response.ok);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('[Vulnerability Details] Error response body:', errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        console.log('[Vulnerability Details] Data received, size:', JSON.stringify(data).length, 'bytes');
        const prettyJson = JSON.stringify(data, null, 2);
        showDetailsModal(`Vulnerability Details: ${vulnerabilityCVE}`, prettyJson);
    } catch (error) {
        console.error('[Vulnerability Details] Error:', error);
        console.error('[Vulnerability Details] Error stack:', error.stack);
        showDetailsModal(`Error`, `Failed to load vulnerability details for ${vulnerabilityCVE}:\n\n${error.message}`);
    }
}

// Fetch and display package details
async function showPackageDetails(packageId, packageName) {
    const url = `/api/packages/${packageId}/details`;
    console.log('[Package Details] Click handler called');
    console.log('[Package Details] ID:', packageId);
    console.log('[Package Details] Name:', packageName);
    console.log('[Package Details] Fetching URL:', url);

    try {
        const response = await fetch(url);
        console.log('[Package Details] Response status:', response.status);
        console.log('[Package Details] Response OK:', response.ok);

        if (!response.ok) {
            const errorText = await response.text();
            console.error('[Package Details] Error response body:', errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        console.log('[Package Details] Data received, size:', JSON.stringify(data).length, 'bytes');
        const prettyJson = JSON.stringify(data, null, 2);
        showDetailsModal(`Package Details: ${packageName}`, prettyJson);
    } catch (error) {
        console.error('[Package Details] Error:', error);
        console.error('[Package Details] Error stack:', error.stack);
        showDetailsModal(`Error`, `Failed to load package details for ${packageName}:\n\n${error.message}`);
    }
}

// DOM ready
document.addEventListener('DOMContentLoaded', initPage);
