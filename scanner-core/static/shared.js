// Shared JavaScript functionality for bjorn2scan UI
// This file contains common code used by images.html, containers.html, etc.

// Global page configuration - must be set by each page before calling init
let pageConfig = {
    apiEndpoint: null,      // e.g., '/api/images' or '/api/containers'
    dataKey: null,          // e.g., 'images' or 'containers'
    pageTitle: null,        // e.g., 'Image Summary' or 'Containers'
    currentPageUrl: null,   // e.g., 'images.html' or 'containers.html'
    defaultSortBy: null,    // e.g., 'image' or 'namespace'
    columnCount: null,      // Total number of columns in the table
    renderRow: null         // Function to render a table row
};

// State management
let currentPage = 1;
let pageSize = 50;
let totalPages = 1;
let totalItems = 0;
let sortBy = null;
let sortOrder = 'ASC';
let multiselectInstances = {}; // Store custom multiselect instances

// Initialize page with configuration
function initSharedPage(config) {
    pageConfig = config;
    sortBy = config.defaultSortBy;
    if (config.defaultSortOrder) {
        sortOrder = config.defaultSortOrder;
    }
}

// Get selected values from multi-select
function getSelectedValues(selectId) {
    const instance = multiselectInstances[selectId];
    return instance ? instance.getSelected() : [];
}

// Custom MultiSelect class
class CustomMultiSelect {
    static instances = []; // Track all instances

    constructor(selectElement, placeholder = 'Select options') {
        this.selectElement = selectElement;
        this.selectElement.style.display = 'none';
        this.placeholder = placeholder;
        this.selected = [];
        this.options = Array.from(selectElement.options).map(opt => ({
            value: opt.value,
            text: opt.text
        }));

        this.createUI();
        this.attachEvents();
        CustomMultiSelect.instances.push(this);
    }

    createUI() {
        this.container = document.createElement('div');
        this.container.className = 'custom-multiselect';

        this.header = document.createElement('div');
        this.header.className = 'multiselect-header';

        this.placeholderElement = document.createElement('span');
        this.placeholderElement.className = 'multiselect-placeholder';
        this.placeholderElement.textContent = this.placeholder;
        this.header.appendChild(this.placeholderElement);

        this.arrow = document.createElement('div');
        this.arrow.className = 'multiselect-arrow';
        this.header.appendChild(this.arrow);

        this.dropdown = document.createElement('div');
        this.dropdown.className = 'multiselect-dropdown';

        this.options.forEach(opt => {
            const optionDiv = document.createElement('div');
            optionDiv.className = 'multiselect-option';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.value = opt.value;
            checkbox.dataset.text = opt.text;

            const label = document.createElement('span');
            label.textContent = opt.text;

            optionDiv.appendChild(checkbox);
            optionDiv.appendChild(label);
            this.dropdown.appendChild(optionDiv);
        });

        this.container.appendChild(this.header);
        this.container.appendChild(this.dropdown);
        this.selectElement.parentNode.insertBefore(this.container, this.selectElement);
    }

    attachEvents() {
        this.header.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggle();
        });

        this.dropdown.addEventListener('click', (e) => {
            e.stopPropagation();
            if (e.target.type === 'checkbox') {
                this.handleSelection(e.target);
            } else if (e.target.closest('.multiselect-option')) {
                const checkbox = e.target.closest('.multiselect-option').querySelector('input');
                checkbox.checked = !checkbox.checked;
                this.handleSelection(checkbox);
            }
        });

        document.addEventListener('click', () => {
            this.close();
        });
    }

    toggle() {
        const isOpening = !this.dropdown.classList.contains('open');
        if (isOpening) {
            CustomMultiSelect.instances.forEach(instance => {
                if (instance !== this) {
                    instance.close();
                }
            });
        }
        this.dropdown.classList.toggle('open');
    }

    close() {
        this.dropdown.classList.remove('open');
    }

    handleSelection(checkbox) {
        const value = checkbox.value;
        const text = checkbox.dataset.text;

        if (checkbox.checked) {
            if (!this.selected.find(s => s.value === value)) {
                this.selected.push({ value, text });
            }
        } else {
            this.selected = this.selected.filter(s => s.value !== value);
        }

        this.updateHeader();
        onFilterChange();
    }

    updateHeader() {
        this.header.innerHTML = '';

        // Toggle .has-selection on the container so CSS can render selected
        // values bolder/darker than the placeholder.
        if (this.selected.length === 0) {
            this.container.classList.remove('has-selection');
            const placeholder = document.createElement('span');
            placeholder.className = 'multiselect-placeholder';
            placeholder.textContent = this.placeholder;
            this.header.appendChild(placeholder);
        } else {
            this.container.classList.add('has-selection');
            const valueSpan = document.createElement('span');
            valueSpan.className = 'multiselect-value';
            valueSpan.textContent = this.selected.map(s => s.text).join(', ');
            this.header.appendChild(valueSpan);
        }

        this.arrow = document.createElement('span');
        this.arrow.className = 'multiselect-arrow';
        this.header.appendChild(this.arrow);
    }

    removeItem(value) {
        this.selected = this.selected.filter(s => s.value !== value);
        const checkbox = this.dropdown.querySelector(`input[value="${value}"]`);
        if (checkbox) checkbox.checked = false;
        this.updateHeader();
        onFilterChange();
    }

    getSelected() {
        return this.selected.map(s => s.value);
    }
}

// Build URL with current filters and sort
function buildQueryParams(includeFormat = false) {
    const params = new URLSearchParams();
    params.append('page', currentPage);
    params.append('pageSize', includeFormat ? 10000 : pageSize);
    params.append('sortBy', sortBy);
    params.append('sortOrder', sortOrder);

    const namespaces = getSelectedValues('namespaceFilter');
    if (namespaces.length) params.append('namespaces', namespaces.join(','));

    const vulnStatuses = getSelectedValues('vulnerabilityStatusFilter');
    if (vulnStatuses.length) params.append('vulnStatuses', vulnStatuses.join(','));

    const packageTypes = getSelectedValues('packageTypeFilter');
    if (packageTypes.length) params.append('packageTypes', packageTypes.join(','));

    const osNames = getSelectedValues('osNameFilter');
    if (osNames.length) params.append('osNames', osNames.join(','));

    if (includeFormat) {
        params.append('format', 'csv');
    }

    return params;
}

// Load filter options. pageConfig.filterOptionsEndpoint lets pages like
// nodes.html point at /api/node-filter-options instead.
async function loadFilterOptions() {
    try {
        const endpoint = pageConfig.filterOptionsEndpoint || '/api/filter-options';
        const response = await fetch(endpoint);
        if (!response.ok) throw new Error('Failed to load filter options');

        const data = await response.json();

        // Each <select> is optional — nodes.html, for example, has no namespace filter.
        const populate = (id, values) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.innerHTML = (values || []).map(v =>
                `<option value="${escapeHtml(v)}">${escapeHtml(v)}</option>`
            ).join('');
        };
        populate('namespaceFilter', data.namespaces);
        populate('vulnerabilityStatusFilter', data.vulnStatuses);
        populate('packageTypeFilter', data.packageTypes);
        populate('osNameFilter', data.osNames);

        initializeMultiselects();

    } catch (error) {
        console.error('Error loading filter options:', error);
    }
}

// Initialize custom multi-select dropdowns
function initializeMultiselects() {
    const filters = [
        { id: 'namespaceFilter', placeholder: 'All namespaces' },
        { id: 'vulnerabilityStatusFilter', placeholder: 'All statuses' },
        { id: 'packageTypeFilter', placeholder: 'All package types' },
        { id: 'osNameFilter', placeholder: 'All distributions' }
    ];

    filters.forEach(filter => {
        const element = document.getElementById(filter.id);
        if (element && !multiselectInstances[filter.id]) {
            multiselectInstances[filter.id] = new CustomMultiSelect(element, filter.placeholder);
        }
    });
}

// Parse URL parameters and apply them to filters
function applyUrlFilters() {
    const urlParams = new URLSearchParams(window.location.search);

    // Map of URL parameter names (both singular and plural) to filter IDs
    const filterMappings = [
        { params: ['namespace', 'namespaces'], filterId: 'namespaceFilter' },
        { params: ['vulnStatus', 'vulnStatuses'], filterId: 'vulnerabilityStatusFilter' },
        { params: ['packageType', 'packageTypes'], filterId: 'packageTypeFilter' },
        { params: ['osName', 'osNames'], filterId: 'osNameFilter' }
    ];

    filterMappings.forEach(mapping => {
        // Try both singular and plural parameter names
        let values = null;
        for (const paramName of mapping.params) {
            const paramValue = urlParams.get(paramName);
            if (paramValue) {
                values = paramValue;
                break;
            }
        }

        if (values) {
            // Split comma-separated values
            const valueArray = values.split(',').map(v => v.trim()).filter(v => v);

            // Get the multiselect instance
            const instance = multiselectInstances[mapping.filterId];
            if (instance) {
                // Check each checkbox that matches a value
                valueArray.forEach(value => {
                    const checkbox = instance.dropdown.querySelector(`input[value="${value}"]`);
                    if (checkbox && !checkbox.checked) {
                        checkbox.checked = true;
                        const text = checkbox.dataset.text;
                        if (!instance.selected.find(s => s.value === value)) {
                            instance.selected.push({ value, text });
                        }
                    }
                });

                // Update the header to show selected items
                instance.updateHeader();
            }
        }
    });
}

// Add cell to row
function addCellToRow(row, align, text) {
    const cell = document.createElement('td');
    cell.style.textAlign = align;
    cell.textContent = text;
    row.appendChild(cell);
    return cell;
}

// ===== Listing-table cell helpers used by images / containers / nodes =====

// Append a right-aligned numeric cell. Renders 0 as a muted "—".
// Returns the <td> so callers can attach a className or title.
function addNumOrDash(row, value) {
    const v = value || 0;
    const cell = document.createElement('td');
    cell.style.textAlign = 'right';
    if (v === 0) {
        cell.innerHTML = '<span class="zero-dash">—</span>';
    } else {
        cell.textContent = formatNumber(v);
    }
    row.appendChild(cell);
    return cell;
}

// Append a right-aligned Risk Score cell. Renders 0 as a muted "—".
function addRiskCell(row, value) {
    const cell = document.createElement('td');
    cell.style.textAlign = 'right';
    if (!value) {
        cell.innerHTML = '<span class="zero-dash">—</span>';
    } else {
        cell.textContent = formatRiskNumber(value);
    }
    row.appendChild(cell);
    return cell;
}

// Append a "CVEs (total / unique)" combo cell. Renders a single "—"
// when both counts are zero.
function addCveComboCell(row, total, unique) {
    const cell = document.createElement('td');
    cell.style.textAlign = 'right';
    cell.className = 'cve-combo';
    if (!total && !unique) {
        cell.innerHTML = '<span class="zero-dash">—</span>';
    } else {
        cell.innerHTML =
            `<span class="cve-total">${formatNumber(total)}</span>` +
            `<span class="cve-sep">/</span>` +
            `<span class="cve-unique">${formatNumber(unique)}</span>`;
    }
    row.appendChild(cell);
    return cell;
}

// Append the "Other" column cell — folds Medium + Low + Negligible +
// Unknown into a single muted number with a tooltip showing the breakdown.
function addOtherCell(row, medium, low, negligible, unknown) {
    const other = (medium || 0) + (low || 0) + (negligible || 0) + (unknown || 0);
    const cell = addNumOrDash(row, other);
    if (other > 0) cell.classList.add('muted-num');
    cell.title = 'Medium: ' + formatNumber(medium) +
                 ' · Low: ' + formatNumber(low) +
                 ' · Negligible: ' + formatNumber(negligible) +
                 ' · Unknown: ' + formatNumber(unknown);
    return cell;
}

// Switch between the Vulnerabilities / SBOM tabs on image.html and
// node.html. Toggles the .active class on the headers and display:none on
// the section bodies, then calls the per-tab filter handler.
function showTab(activeId, hiddenId, onActive) {
    document.getElementById(activeId.section).style.display = 'block';
    document.getElementById(hiddenId.section).style.display = 'none';
    document.getElementById(activeId.header).classList.add('active');
    document.getElementById(hiddenId.header).classList.remove('active');
    if (typeof onActive === 'function') onActive();
}

// Append a two-line left-aligned cell — bold-ish primary on top,
// muted secondary below. Used for image (name + tag), pod (namespace/pod
// + container), and node (name + OS distribution).
function addTwoLineCell(row, primary, secondary) {
    const cell = document.createElement('td');
    cell.style.textAlign = 'left';
    cell.innerHTML =
        `<div class="img-name">${escapeHtml(primary || '')}</div>` +
        (secondary ? `<div class="img-tag">${escapeHtml(secondary)}</div>` : '');
    row.appendChild(cell);
    return cell;
}

// Format number with commas
function formatNumber(num) {
    if (num === null || num === undefined || num === 0) return '0';
    return num.toLocaleString();
}

// Format risk number with commas (x,xxx.0 format, or "< 0.1" for small values)
function formatRiskNumber(risk) {
    if (risk === null || risk === undefined || risk === 0) {
        return '0.0';
    }
    if (risk < 0.1) {
        return '< 0.1';
    }
    // Format with commas and one decimal place
    return risk.toLocaleString('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 });
}

// Format timestamp to a readable date/time string
// Input is expected to be an ISO 8601 / RFC 3339 timestamp string
function formatTimestamp(timestamp) {
    if (!timestamp) return '-';
    try {
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return '-';
        // Format as "Jan 5, 2026 14:30" (locale-aware, compact)
        return date.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        }) + ' ' + date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: false
        });
    } catch (e) {
        return '-';
    }
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

// Check if scan is complete based on status description
function isScanComplete(statusDescription) {
    return statusDescription === 'Scan complete';
}

// Load data table. Handles two response shapes:
//   - paginated object: { [dataKey]: [...], totalPages, totalCount, page }
//   - bare array: [...]  (used by /api/summary/by-node which lacks server-side
//     pagination/sort) — we sort and paginate client-side.
async function loadDataTable() {
    const tableBody = document.querySelector('#vulnerabilityTable tbody');

    try {
        const params = buildQueryParams(false);
        const response = await fetch(`${pageConfig.apiEndpoint}?${params}`);

        if (!response.ok) {
            throw new Error(`Failed to load data: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        tableBody.innerHTML = '';

        let items;
        if (Array.isArray(data)) {
            items = data.slice();
            items.sort((a, b) => {
                let av = a[sortBy], bv = b[sortBy];
                if (typeof av === 'string') {
                    av = av.toLowerCase();
                    bv = (bv || '').toLowerCase();
                }
                if (av < bv) return sortOrder === 'ASC' ? -1 : 1;
                if (av > bv) return sortOrder === 'ASC' ? 1 : -1;
                return 0;
            });
            totalItems = items.length;
            totalPages = Math.ceil(totalItems / pageSize) || 1;
            const start = (currentPage - 1) * pageSize;
            items = items.slice(start, start + pageSize);
        } else {
            items = data[pageConfig.dataKey] || [];
            totalPages = data.totalPages || 1;
            totalItems = data.totalCount || 0;
            currentPage = data.page || currentPage;
        }

        items.forEach(item => {
            const row = document.createElement('tr');
            row.classList.add('clickable-row');
            pageConfig.renderRow(row, item);
            tableBody.appendChild(row);
        });

        renderPagination();

    } catch (error) {
        console.error('Error loading data:', error);
        tableBody.innerHTML = '';
        const row = document.createElement('tr');
        const cell = addCellToRow(row, 'left', '⚠️ Error loading data: ' + error.message);
        cell.colSpan = pageConfig.columnCount;
        cell.style.color = 'red';
        tableBody.appendChild(row);
        renderPagination();
    }
}

// Default deployment-metrics → stats array. Pages can override by setting
// pageConfig.summaryStatsBuilder to a fn(metrics) => [[label, formattedValue], ...].
function defaultSummaryStats(m) {
    const stats = [
        ['Images', formatNumber(m.images_scanned || 0)],
        ['Containers', formatNumber(m.container_instances || 0)],
        ['CVEs', formatNumber(m.total_cves || 0)],
        ['Unique CVEs', formatNumber(m.unique_cves || 0)],
        ['Exploits', formatNumber(m.total_exploits || 0)],
    ];
    if (m.images_pending) stats.push(['Pending', formatNumber(m.images_pending)]);
    if (m.images_failed)  stats.push(['Failed',  formatNumber(m.images_failed)]);
    return stats;
}

// Load the filtered summary bar (if present on this page).
// pageConfig.summaryEndpoint and pageConfig.summaryStatsBuilder allow pages
// like nodes.html to point at a different endpoint with a different shape.
async function loadImageSummary() {
    const div = document.getElementById('imageSummary');
    if (!div) return;

    try {
        const endpoint = pageConfig.summaryEndpoint || '/api/summary/deployment-metrics';
        const response = await fetch(endpoint + getCurrentFilterQueryString());
        if (!response.ok) return;
        const m = await response.json();

        const builder = pageConfig.summaryStatsBuilder || defaultSummaryStats;
        const stats = builder(m);

        div.innerHTML = stats
            .map(([label, value]) => `<div class="stat"><div class="stat-label">${escapeHtml(label)}</div><div class="stat-value">${value}</div></div>`)
            .join('');
    } catch (e) {
        console.error('Error loading summary:', e);
    }
}

// Handle filter changes
function onFilterChange() {
    currentPage = 1;
    loadDataTable();
    loadImageSummary();
    updateCSVLink();
    renderSidebarNav(); // Update navigation links with current filters
}

// Pagination functions
function goToPage(page) {
    if (page < 1 || page > totalPages) return;
    currentPage = page;
    loadDataTable();
}

function nextPage() {
    if (currentPage < totalPages) {
        currentPage++;
        loadDataTable();
    }
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadDataTable();
    }
}

function renderPagination() {
    const paginationDiv = document.getElementById('pagination');
    if (!paginationDiv) return;

    if (totalPages <= 1) {
        paginationDiv.innerHTML = '';
        return;
    }

    let html = '<div style="display: flex; justify-content: center; align-items: center; gap: 10px;">';

    html += `<button onclick="prevPage()" ${currentPage === 1 ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === 1 ? 'default' : 'pointer'};">Previous</button>`;

    html += '<div style="display: flex; gap: 5px;">';

    if (currentPage > 3) {
        html += `<button onclick="goToPage(1)" style="padding: 5px 10px; cursor: pointer;">1</button>`;
        if (currentPage > 4) {
            html += `<span style="padding: 5px;">...</span>`;
        }
    }

    for (let i = Math.max(1, currentPage - 2); i <= Math.min(totalPages, currentPage + 2); i++) {
        if (i === currentPage) {
            html += `<button style="padding: 5px 10px; font-weight: bold; background: lightgrey;">${i}</button>`;
        } else {
            html += `<button onclick="goToPage(${i})" style="padding: 5px 10px; cursor: pointer;">${i}</button>`;
        }
    }

    if (currentPage < totalPages - 2) {
        if (currentPage < totalPages - 3) {
            html += `<span style="padding: 5px;">...</span>`;
        }
        html += `<button onclick="goToPage(${totalPages})" style="padding: 5px 10px; cursor: pointer;">${totalPages}</button>`;
    }

    html += '</div>';

    html += `<button onclick="nextPage()" ${currentPage === totalPages ? 'disabled' : ''} style="padding: 5px 10px; cursor: ${currentPage === totalPages ? 'default' : 'pointer'};">Next</button>`;

    const startItem = (currentPage - 1) * pageSize + 1;
    const endItem = Math.min(currentPage * pageSize, totalItems);
    html += `<span style="margin-left: 20px; color: #666;">Showing ${startItem}-${endItem} of ${totalItems}</span>`;

    html += '</div>';

    paginationDiv.innerHTML = html;
}

// Update CSV export link
function updateCSVLink() {
    const params = buildQueryParams(true);
    document.getElementById('csvlink').href = `${pageConfig.apiEndpoint}?${params}`;
}

// Sort by column
function sortByColumn(column) {
    if (sortBy === column) {
        sortOrder = sortOrder === 'ASC' ? 'DESC' : 'ASC';
    } else {
        sortBy = column;
        sortOrder = 'ASC';
    }
    updateSortIndicators();
    loadDataTable();
}

// Update sort indicators on column headers
function updateSortIndicators() {
    document.querySelectorAll('th.sortable').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.sortField === sortBy) {
            th.classList.add(sortOrder === 'ASC' ? 'sort-asc' : 'sort-desc');
        }
    });
}

// Global config storage
let appConfig = {
    clusterName: 'bjorn2scan',
    version: '1.0.0',
    scanContainers: true,
    scanNodes: false
};

// Load configuration from API
async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        if (!response.ok) {
            throw new Error('Failed to load config');
        }
        const data = await response.json();

        appConfig.clusterName = data.clusterName || appConfig.clusterName;
        appConfig.version = data.version || appConfig.version;
        appConfig.scanContainers = data.scanContainers !== undefined ? data.scanContainers : appConfig.scanContainers;
        appConfig.scanNodes = data.scanNodes !== undefined ? data.scanNodes : appConfig.scanNodes;

        const clusterNameDiv = document.getElementById('clusterName');
        clusterNameDiv.textContent = pageConfig.pageTitle + ' - ' + appConfig.clusterName;

        document.title = pageConfig.pageTitle + ' - ' + appConfig.clusterName;

    } catch (error) {
        console.error('Error loading config:', error);
    }

    // Start monitoring DB initialization status
    checkDBStatus();
}

// Poll /api/db/status and show a banner while the vulnerability database is initializing.
// Removes itself automatically once the database becomes available.
async function checkDBStatus() {
    try {
        const response = await fetch('/api/db/status');
        if (!response.ok) return; // Endpoint not present - nothing to show

        const status = await response.json();
        const bannerId = 'db-init-banner';
        let banner = document.getElementById(bannerId);

        if (status.available) {
            if (banner) banner.remove();
            return; // Database is ready - stop polling
        }

        // Database not ready - show banner
        if (!banner) {
            banner = document.createElement('div');
            banner.id = bannerId;
            banner.style.cssText = [
                'background:#f0f0f0',
                'border:1px solid #999',
                'padding:10px 16px',
                'margin-bottom:16px',
                'border-radius:4px',
                'color:#333',
                'font-size:14px',
            ].join(';');
            const h1 = document.querySelector('h1');
            if (h1 && h1.parentNode) {
                h1.parentNode.insertBefore(banner, h1.nextSibling);
            }
        }
        banner.textContent = 'Vulnerability database is initializing. Scans will begin automatically once the database is ready.';

        // Check again in 5 seconds
        setTimeout(checkDBStatus, 5000);
    } catch (e) {
        // Silent fail - don't disrupt the page if this endpoint is unreachable
    }
}

// Get current filter query string for navigation links
function getCurrentFilterQueryString() {
    const params = new URLSearchParams();

    const namespaces = getSelectedValues('namespaceFilter');
    if (namespaces.length) params.append('namespaces', namespaces.join(','));

    const vulnStatuses = getSelectedValues('vulnerabilityStatusFilter');
    if (vulnStatuses.length) params.append('vulnStatuses', vulnStatuses.join(','));

    const packageTypes = getSelectedValues('packageTypeFilter');
    if (packageTypes.length) params.append('packageTypes', packageTypes.join(','));

    const osNames = getSelectedValues('osNameFilter');
    if (osNames.length) params.append('osNames', osNames.join(','));

    // Severity exists only on the CVE pages (no severityFilter elsewhere → []).
    // The deployment-metrics / node-metrics summaries now honor it.
    const severities = getSelectedValues('severityFilter');
    if (severities.length) params.append('severity', severities.join(','));

    const queryString = params.toString();
    return queryString ? '?' + queryString : '';
}

// Render sidebar navigation
function renderSidebarNav() {
    const tableBody = document.getElementById('sidebarNav');
    if (!tableBody) return;

    tableBody.innerHTML = '';

    const showContainerScans = appConfig.scanContainers;
    const showNodeScans = appConfig.scanNodes;

    function addNavItem(title, url, includeFilters = false) {
        const row = document.createElement('tr');
        const cell = document.createElement('td');

        // Extract base page name from URL (e.g., 'images.html' from 'images.html')
        const basePage = url.split('?')[0];
        const isCurrentPage = basePage === pageConfig.currentPageUrl;
        const decoration = isCurrentPage ? '<u>' : '';
        const decorationEnd = isCurrentPage ? '</u>' : '';

        // Add filters to Images and Containers links
        let fullUrl = url;
        if (includeFilters) {
            fullUrl = basePage + getCurrentFilterQueryString();
        }

        cell.innerHTML = `<h2><a href="${fullUrl}">${decoration}${title}${decorationEnd}</a></h2>`;
        row.appendChild(cell);
        tableBody.appendChild(row);
    }

    addNavItem('Summary', 'index.html');
    if (showContainerScans) {
        addNavItem('Images', 'images.html', true);
        addNavItem('Containers', 'containers.html', true);
        addNavItem('Container CVEs', 'container_cves.html', true);
    }
    if (showNodeScans) {
        addNavItem('Nodes', 'nodes.html');
        addNavItem('Node CVEs', 'node_cves.html', true);
    }
}

// Render top-bar navigation (horizontal). Used by pages that opt into
// the top-bar layout via #topbarNav; sidebar pages still use renderSidebarNav.
function renderTopBarNav() {
    const container = document.getElementById('topbarNav');
    if (!container) return;
    container.innerHTML = '';

    const showContainerScans = appConfig.scanContainers;
    const showNodeScans = appConfig.scanNodes;

    function addNavItem(title, url, includeFilters = false) {
        const basePage = url.split('?')[0];
        const isCurrentPage = basePage === pageConfig.currentPageUrl;
        const fullUrl = includeFilters ? basePage + getCurrentFilterQueryString() : url;

        const a = document.createElement('a');
        a.href = fullUrl;
        a.textContent = title;
        if (isCurrentPage) a.classList.add('active');
        container.appendChild(a);
    }

    addNavItem('Summary', 'index.html');
    if (showContainerScans) {
        addNavItem('Images', 'images.html', true);
        addNavItem('Containers', 'containers.html', true);
        addNavItem('Container CVEs', 'container_cves.html', true);
    }
    if (showNodeScans) {
        addNavItem('Nodes', 'nodes.html');
        addNavItem('Node CVEs', 'node_cves.html', true);
    }
}

// Render version footer
function renderVersionFooter() {
    const html = `<p style="text-align: right; color: #666; font-style: italic;"><a href="https://github.com/bvboe/b2s-go" target="_blank" style="color: #666; text-decoration: underline;">Bjørn2Scan v${appConfig.version}</a></p>`;
    // Support both single (#app-footer) and multiple (.app-footer) slots — e.g. image.html
    // and node.html have two tab sections, each needing its own bottom-aligned footer.
    document.querySelectorAll('#app-footer, .app-footer').forEach(el => {
        el.innerHTML = html;
    });
}

// Auto-refresh functionality
let currentTimestamp = null;

async function checkForUpdates() {
    try {
        const response = await fetch("/api/lastupdated?datatype=image");
        if (!response.ok) {
            console.error("Failed to fetch last updated timestamp");
            return;
        }

        const newTimestamp = await response.text();

        if (currentTimestamp === null) {
            // First time - just store the timestamp
            currentTimestamp = newTimestamp;
        } else if (newTimestamp !== currentTimestamp) {
            // Timestamp changed - reload data
            console.log("Data updated, reloading...");
            currentTimestamp = newTimestamp;
            loadDataTable();
            loadImageSummary();
        }
    } catch (error) {
        console.error("Error checking for updates:", error);
    }
}

// Initialize page
async function initPage() {
    await loadConfig();
    renderSidebarNav();
    renderTopBarNav();
    renderVersionFooter();
    await loadFilterOptions();

    // Apply URL parameters to filters after multiselects are initialized
    applyUrlFilters();

    // Update navigation with URL filters
    renderSidebarNav();
    renderTopBarNav();

    loadDataTable();
    loadImageSummary();
    updateCSVLink();
    updateSortIndicators();

    // Start polling for updates every 2 seconds
    setInterval(checkForUpdates, 2000);
}
