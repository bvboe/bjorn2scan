// Container CVEs page — deployment-wide, deduplicated CVE listing across all
// running containers. Mirrors the image.html vulnerabilities table, but scoped
// to the whole deployment with namespace/OS filters and an affected-images
// details view. Reuses helpers from shared.js (loadConfig, renderTopBarNav,
// loadImageSummary, CustomMultiSelect, applyUrlFilters, addCellToRow, etc.).

let cveState = {
    page: 1,
    pageSize: 100,
    sortBy: 'vulnerability_severity',
    sortOrder: 'ASC',
};

// Initialize page
async function initPage() {
    pageConfig.pageTitle = 'Container CVEs';
    pageConfig.currentPageUrl = 'container_cves.html';

    await loadConfig();
    renderTopBarNav();
    await loadFilterOptions();
    applyUrlFilters();      // honor filters passed via cross-page nav links
    renderTopBarNav();      // refresh nav links with the applied filters

    loadCVEsTable();
    loadImageSummary();
    updateCVEExportLink();
    updateCVESortIndicators();
    renderVersionFooter();
}

// Populate the five filter multiselects from /api/filter-options.
async function loadFilterOptions() {
    try {
        const response = await fetch('/api/filter-options');
        if (!response.ok) throw new Error('Failed to load filter options');
        const data = await response.json();

        const fill = (id, values) => {
            const sel = document.getElementById(id);
            sel.innerHTML = (values || []).map(v =>
                `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`
            ).join('');
        };

        fill('namespaceFilter', data.namespaces);
        fill('osNameFilter', data.osNames);
        fill('severityFilter', ['Critical', 'High', 'Medium', 'Low', 'Negligible', 'Unknown']);
        fill('vulnerabilityStatusFilter', data.vulnStatuses);
        fill('packageTypeFilter', data.packageTypes);

        multiselectInstances['namespaceFilter']           = new CustomMultiSelect(document.getElementById('namespaceFilter'), 'All namespaces');
        multiselectInstances['osNameFilter']              = new CustomMultiSelect(document.getElementById('osNameFilter'), 'All distributions');
        multiselectInstances['severityFilter']            = new CustomMultiSelect(document.getElementById('severityFilter'), 'All severities');
        multiselectInstances['vulnerabilityStatusFilter'] = new CustomMultiSelect(document.getElementById('vulnerabilityStatusFilter'), 'All statuses');
        multiselectInstances['packageTypeFilter']         = new CustomMultiSelect(document.getElementById('packageTypeFilter'), 'All types');
    } catch (error) {
        console.error('Error loading filter options:', error);
    }
}

// Build the query string for the CVE listing. The four shared filters use the
// same param names as the rest of the app (so the summary strip and nav links
// stay consistent); severity is the one CVE-specific filter.
function buildCVEParams(forExport) {
    const params = new URLSearchParams({
        sortBy: cveState.sortBy,
        sortOrder: cveState.sortOrder,
    });
    if (forExport) {
        params.set('page', 1);
        params.set('pageSize', 10000);
    } else {
        params.set('page', cveState.page);
        params.set('pageSize', cveState.pageSize);
    }

    const namespaces   = getSelectedValues('namespaceFilter');
    const osNames      = getSelectedValues('osNameFilter');
    const severities   = getSelectedValues('severityFilter');
    const vulnStatuses = getSelectedValues('vulnerabilityStatusFilter');
    const packageTypes = getSelectedValues('packageTypeFilter');

    if (namespaces.length)   params.append('namespaces', namespaces.join(','));
    if (osNames.length)      params.append('osNames', osNames.join(','));
    if (severities.length)   params.append('severity', severities.join(','));
    if (vulnStatuses.length) params.append('vulnStatuses', vulnStatuses.join(','));
    if (packageTypes.length) params.append('packageTypes', packageTypes.join(','));

    return params;
}

// Load the CVE listing table
async function loadCVEsTable() {
    const tableBody = document.querySelector('#cvesTable tbody');

    try {
        const response = await fetch(`/api/container-cves?${buildCVEParams(false)}`);
        if (!response.ok) throw new Error(`Failed to load CVEs: ${response.status}`);

        const data = await response.json();
        tableBody.innerHTML = '';

        (data.cves || []).forEach(vuln => {
            const row = document.createElement('tr');
            row.classList.add('clickable-row');
            row.style.cursor = 'pointer';
            row.onclick = function() { showCVEDetails(vuln); };

            addCellToRow(row, 'left', vuln.vulnerability_severity || '');
            addCellToRow(row, 'left', vuln.vulnerability_id || '');
            addCellToRow(row, 'left', vuln.artifact_name || '');
            addCellToRow(row, 'left', vuln.artifact_version || '');
            addCellToRow(row, 'left', vuln.vulnerability_fix_versions || '');
            addCellToRow(row, 'left', vuln.vulnerability_fix_state || '');
            addCellToRow(row, 'left', vuln.artifact_type || '');
            addCellToRow(row, 'right', formatRiskNumber(vuln.vulnerability_risk));
            addCellToRow(row, 'right', formatNumber(vuln.vulnerability_known_exploits));
            addCellToRow(row, 'right', formatNumber(vuln.vulnerability_count));

            tableBody.appendChild(row);
        });

        renderCVEPagination(data.page || 1, data.totalPages || 1, data.totalCount || 0);
    } catch (error) {
        console.error('Error loading CVEs:', error);
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', '⚠️ Error loading CVEs: ' + error.message);
        cell.colSpan = 10;
        cell.style.color = 'red';
        tableBody.appendChild(row);
    }
}

// Filter change handler (wired from the <select> onchange in the HTML)
function onFilterChange() {
    cveState.page = 1;
    loadCVEsTable();
    loadImageSummary();
    updateCVEExportLink();
    renderTopBarNav();
}

// Sorting
function sortCVEByColumn(field) {
    if (cveState.sortBy === field) {
        cveState.sortOrder = cveState.sortOrder === 'ASC' ? 'DESC' : 'ASC';
    } else {
        cveState.sortBy = field;
        cveState.sortOrder = 'ASC';
    }
    cveState.page = 1;
    updateCVESortIndicators();
    loadCVEsTable();
}

function updateCVESortIndicators() {
    document.querySelectorAll('#cvesTable th.sortable').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.sortField === cveState.sortBy) {
            th.classList.add(cveState.sortOrder === 'ASC' ? 'sort-asc' : 'sort-desc');
        }
    });
}

// CSV export link (no JSON export for this page)
function updateCVEExportLink() {
    const params = buildCVEParams(true);
    document.getElementById('cvecsvlink').href = `/api/container-cves?${params}&format=csv`;
}

// Pagination
function goToCVEPage(page) {
    if (page < 1) return;
    cveState.page = page;
    loadCVEsTable();
}
function prevCVEPage() {
    if (cveState.page > 1) { cveState.page--; loadCVEsTable(); }
}
function nextCVEPage(totalPages) {
    if (cveState.page < totalPages) { cveState.page++; loadCVEsTable(); }
}

function renderCVEPagination(currentPage, totalPages, totalCount) {
    const paginationDiv = document.getElementById('pagination');
    if (!paginationDiv) return;

    if (totalPages <= 1) {
        paginationDiv.innerHTML = '';
        return;
    }

    let html = '<div style="display: flex; justify-content: center; align-items: center; gap: 10px;">';
    html += `<button onclick="prevCVEPage()" ${currentPage === 1 ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === 1 ? 'default' : 'pointer'};">Previous</button>`;
    html += '<div style="display: flex; gap: 5px;">';

    if (currentPage > 3) {
        html += `<button onclick="goToCVEPage(1)" style="padding: 5px 10px; cursor: pointer;">1</button>`;
        if (currentPage > 4) html += `<span style="padding: 5px;">...</span>`;
    }
    for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
        if (i === currentPage) {
            html += `<button style="padding: 5px 10px; font-weight: bold; background: lightgrey;">${i}</button>`;
        } else {
            html += `<button onclick="goToCVEPage(${i})" style="padding: 5px 10px; cursor: pointer;">${i}</button>`;
        }
    }
    if (currentPage < totalPages - 2) {
        if (currentPage < totalPages - 3) html += `<span style="padding: 5px;">...</span>`;
        html += `<button onclick="goToCVEPage(${totalPages})" style="padding: 5px 10px; cursor: pointer;">${totalPages}</button>`;
    }
    html += '</div>';
    html += `<button onclick="nextCVEPage(${totalPages})" ${currentPage === totalPages ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === totalPages ? 'default' : 'pointer'};">Next</button>`;

    const startItem = (currentPage - 1) * cveState.pageSize + 1;
    const endItem = Math.min(currentPage * cveState.pageSize, totalCount);
    html += `<span style="margin-left: 20px; color: #666;">Showing ${startItem}-${endItem} of ${totalCount}</span>`;
    html += '</div>';

    paginationDiv.innerHTML = html;
}

// ===== Details modal =====

function closeDetailsModal() {
    document.getElementById('detailsModal').style.display = 'none';
}

window.onclick = function(event) {
    const modal = document.getElementById('detailsModal');
    if (event.target === modal) closeDetailsModal();
};

// Show the CVE details modal: affected images/namespaces + distinct detail variants.
async function showCVEDetails(vuln) {
    document.getElementById('modalTitle').textContent = `CVE Details: ${vuln.vulnerability_id || ''}`;
    const affectedDiv = document.getElementById('modalAffected');
    const variantsDiv = document.getElementById('modalVariants');
    affectedDiv.innerHTML = '<em>Loading affected images…</em>';
    variantsDiv.innerHTML = '';
    document.getElementById('detailsModal').style.display = 'block';

    loadAffected(vuln, affectedDiv);
    loadVariants(vuln, variantsDiv);
}

// Build the shared CVE-identifying query params for the affected / details endpoints.
function cveDetailParams(vuln) {
    const params = new URLSearchParams({ cve: vuln.vulnerability_id || '' });
    if (vuln.artifact_name)    params.set('name', vuln.artifact_name);
    if (vuln.artifact_version) params.set('version', vuln.artifact_version);
    if (vuln.artifact_type)    params.set('type', vuln.artifact_type);
    return params;
}

// Affected images & namespaces table
async function loadAffected(vuln, affectedDiv) {
    const params = cveDetailParams(vuln);

    try {
        const response = await fetch(`/api/container-cves/affected?${params}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        const rows = data.affected || [];

        affectedDiv.innerHTML = '';
        const heading = document.createElement('b');
        heading.textContent = 'Affected images & namespaces';
        affectedDiv.appendChild(heading);

        if (rows.length === 0) {
            const none = document.createElement('div');
            none.innerHTML = '<em>No affected containers found.</em>';
            affectedDiv.appendChild(none);
            return;
        }

        const table = document.createElement('table');
        table.className = 'listingTable';
        table.style.marginTop = '8px';
        table.innerHTML = '<thead><tr>'
            + '<th class="text-col"><b>Namespace</b></th>'
            + '<th class="text-col"><b>Image</b></th>'
            + '<th class="text-col"><b>Containers</b></th>'
            + '</tr></thead>';

        const tbody = document.createElement('tbody');
        rows.forEach(r => {
            const tr = document.createElement('tr');
            addCellToRow(tr, 'left', r.namespace || '');
            addCellToRow(tr, 'left', r.reference || r.digest || '');
            addCellToRow(tr, 'left', formatNumber(r.container_count));

            // Click through to the selected image's detail page.
            if (r.digest) {
                tr.classList.add('clickable-row');
                tr.style.cursor = 'pointer';
                tr.title = 'View image details';
                tr.onclick = function() {
                    window.location.href = 'image.html?imageid=' + encodeURIComponent(r.digest);
                };
            }
            tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        affectedDiv.appendChild(table);
    } catch (error) {
        console.error('Error loading affected images:', error);
        affectedDiv.innerHTML = `<em>Failed to load affected images: ${escapeHtml(error.message)}</em>`;
    }
}

// Distinct detail-JSON variants across affected images. Identical records are
// collapsed server-side; each variant lists (and links to) the images that share it.
async function loadVariants(vuln, container) {
    container.innerHTML = '<em>Loading details…</em>';

    try {
        const response = await fetch(`/api/container-cves/details?${cveDetailParams(vuln)}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        const variants = data.variants || [];

        container.innerHTML = '';
        if (variants.length === 0) {
            container.innerHTML = '<em>No detail records available.</em>';
            return;
        }

        variants.forEach((variant, idx) => {
            const images = variant.images || [];

            const block = document.createElement('div');
            block.style.marginBottom = '14px';

            // Header: "Variant N of M (k images)"
            const header = document.createElement('div');
            header.style.marginBottom = '4px';
            const label = document.createElement('b');
            label.textContent = `Variant ${idx + 1} of ${variants.length} (${images.length} image${images.length === 1 ? '' : 's'})`;
            header.appendChild(label);
            block.appendChild(header);

            // Linked image list (click → that image's detail page)
            if (images.length) {
                const imgList = document.createElement('div');
                imgList.style.cssText = 'font-size: 12px; color: #444; margin-bottom: 4px;';
                images.forEach((im, i) => {
                    const a = document.createElement('a');
                    a.href = 'image.html?imageid=' + encodeURIComponent(im.digest || '');
                    a.textContent = im.reference || im.digest || '(unknown image)';
                    a.title = im.digest || '';
                    imgList.appendChild(a);
                    if (i < images.length - 1) imgList.appendChild(document.createTextNode(', '));
                });
                block.appendChild(imgList);
            }

            // Pretty-printed detail JSON
            const box = document.createElement('div');
            box.style.cssText = 'background-color: #f5f5f5; padding: 12px; border: 1px solid #ddd; overflow: auto;';
            const pre = document.createElement('pre');
            pre.style.cssText = 'margin: 0; font-family: monospace; font-size: 12px; white-space: pre-wrap; word-wrap: break-word;';
            try {
                pre.textContent = JSON.stringify(variant.details, null, 2);
            } catch (e) {
                pre.textContent = String(variant.details);
            }
            box.appendChild(pre);
            block.appendChild(box);

            container.appendChild(block);
        });
    } catch (error) {
        console.error('Error loading detail variants:', error);
        container.innerHTML = `<em>Failed to load details: ${escapeHtml(error.message)}</em>`;
    }
}

document.addEventListener('DOMContentLoaded', initPage);
