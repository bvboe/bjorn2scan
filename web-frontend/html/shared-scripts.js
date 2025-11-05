// Cache object to store the fetched configuration
const configCache = {};

async function loadNamespaceTable(currentUrl, currentNamespace) {
    console.log("loadNamespaceTable()")
    const response = await fetch("/api/namespaces");
    console.log("loadNamespaceTable() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();
    //console.log(data)

    const select = document.getElementById("namespaceSelect")

    // Get current filters except namespace
    const filters = getCurrentFilters();
    delete filters.namespace; // Remove namespace as we're setting it explicitly

    addNamespaceSelect(select, "All Namespaces", buildUrlWithFilters(currentUrl, filters), currentNamespace, false);
    addNamespaceSelect(select, "─────", currentUrl, currentNamespace, true);
    data.forEach(item => {
        const namespaceFilters = {...filters, namespace: item};
        addNamespaceSelect(select, item, buildUrlWithFilters(currentUrl, namespaceFilters), currentNamespace, false);
    });
}

function addNamespaceSelect(select, namespace, namespaceUrl, selectedNamespace, disabled) {
    var option = document.createElement("option");

    // Set the text and value
    option.text = namespace;
    option.value = namespaceUrl;

    if (selectedNamespace == namespace) {
        option.selected = true;
    }
    option.disabled = disabled;
    
    // Add the option to the select element
    select.add(option);
}

function getCurrentFilters() {
    // Get current filters from dropdown selections, not from URL
    const filters = {};

    const filterMappings = [
        { param: 'namespace', filterId: 'namespaceFilter' },
        { param: 'fixstatus', filterId: 'vulnerabilityStatusFilter' },
        { param: 'packagetype', filterId: 'packageTypeFilter' },
        { param: 'severity', filterId: 'vulnerabilitySeverityFilter' },
        { param: 'distributiondisplayname', filterId: 'distributionDisplayNameFilter' }
    ];

    filterMappings.forEach(mapping => {
        const filterElement = document.getElementById(mapping.filterId);
        if (filterElement) {
            const selectedValues = $('#' + mapping.filterId).val();
            if (selectedValues && selectedValues.length > 0) {
                filters[mapping.param] = selectedValues.join(',');
            }
        }
    });

    return filters;
}

function buildUrlWithFilters(baseUrl, filters) {
    if (!filters || Object.keys(filters).length === 0) {
        return baseUrl;
    }

    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
        params.append(key, value);
    }

    return baseUrl + "?" + params.toString();
}

function doRenderHeaderCell(tableBody, title, url, currentUrl, currentFilters) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");

    // Build URL with current filters
    const fullUrl = buildUrlWithFilters(url, currentFilters);

    if(currentUrl == url) {
        decorationFront="<u>"
        decorationEnd="</u>"
    } else {
        decorationFront=""
        decorationEnd=""
    }
    cell.innerHTML = "<h2><a href=\"" + fullUrl + "\">" + decorationFront + title + decorationEnd + "</a></h2>";
    row.appendChild(cell);
    tableBody.appendChild(row);
}

async function renderSectionTable(currentUrl) {
    const tableBody = document.querySelector("#headerTable tbody");
    tableBody.replaceChildren();

    const doShowContainerScans = await showContainerScans();
    const doShowNodeScans = await showNodeScans();
    console.log("container scans - " + doShowContainerScans);
    console.log("node scans - " + doShowNodeScans);

    // Get current filters to preserve when navigating
    const currentFilters = getCurrentFilters();

    doRenderHeaderCell(tableBody, "Summary", "index.html", currentUrl, currentFilters);
    if (doShowContainerScans) {
        doRenderHeaderCell(tableBody, "Images", "images.html", currentUrl, currentFilters);
        doRenderHeaderCell(tableBody, "Pods", "pods.html", currentUrl, currentFilters);
    }
    if (doShowNodeScans) {
        doRenderHeaderCell(tableBody, "Nodes", "nodes.html", currentUrl, currentFilters);
    }
    if (doShowContainerScans) {
        doRenderHeaderCell(tableBody, "CVEs", "cves.html", currentUrl, currentFilters);
        doRenderHeaderCell(tableBody, "SBOM", "sbom.html", currentUrl, currentFilters);
    }
}

function formatNumber(num, digits = 0) {
    return num.toLocaleString('en-US', { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

function formatRiskNumber(risk) {
    if (risk === 0) {
        return "0.0";
    }
    if (risk < 0.1) {
        return "< 0.1";
    }
    return risk.toFixed(1);
}

function onNamespaceChange(selectedNamespace) {
    window.location.href = selectedNamespace;
}

async function initClusterName(pageTitle) {
    console.log("initClusterName()");
    try {
        const clusterName = await getConfigProperty("clusterName")
        const clusternameDiv = document.getElementById("clusterName");
        clusternameDiv.innerText = pageTitle + " - " + clusterName;
    } catch (error) {
        console.error("Error initializing cluster name:", error);
        const clusternameDiv = document.getElementById("clusterName");
        clusternameDiv.innerText = pageTitle + " - Unknown Cluster";
    }
}

async function initFilters(urlFilters = {}) {
    try {
        const response = await fetch("/api/filters");
        if (!response.ok) {
            throw new Error(`Failed to load filters: ${response.status} ${response.statusText}`);
        }
        const filterData = await response.json();
        initSelect("namespaceFilter", filterData.namespaces, urlFilters.namespaceFilter);
        initSelect("vulnerabilityStatusFilter", filterData['fix-states'], urlFilters.vulnerabilityStatusFilter);
        initSelect("packageTypeFilter", filterData['unique-packages'], urlFilters.packageTypeFilter);
        initSelect("vulnerabilitySeverityFilter", filterData['severities'], urlFilters.vulnerabilitySeverityFilter);
        initSelect("distributionDisplayNameFilter", filterData['distribution-display-names'], urlFilters.distributionDisplayNameFilter);

        if ($('#categories').length) {
            $('#categories').multiSelect({
                noneText: 'All categories',
                presets: [
                    {
                        name: 'All categories',
                        all: true
                    }
                ]
            });
        }
        if ($('#namespaceFilter').length) {
            $('#namespaceFilter').multiSelect({
                noneText: 'All namespaces',
                presets: [
                    {
                        name: 'All namespaces',
                        all: true
                    }
                ]
            });
        }
        if ($('#vulnerabilityStatusFilter').length) {
            $('#vulnerabilityStatusFilter').multiSelect({
                noneText: 'All statuses',
                presets: [
                    {
                        name: 'All statuses',
                        all: true
                    }
                ]
            });
        }
        if ($('#packageTypeFilter').length) {
            $('#packageTypeFilter').multiSelect({
                noneText: 'All package types',
                presets: [
                    {
                        name: 'All package types',
                        all: true
                    }
                ]
            });
        }
        if ($('#vulnerabilitySeverityFilter').length) {
            $('#vulnerabilitySeverityFilter').multiSelect({
                noneText: 'All severities',
                presets: [
                    {
                        name: 'All severities',
                        all: true
                    }
                ]
            });
        }
        if ($('#distributionDisplayNameFilter').length) {
            $('#distributionDisplayNameFilter').multiSelect({
                noneText: 'All operating systems',
                presets: [
                    {
                        name: 'All operating systems',
                        all: true
                    }
                ]
            });
        }
    } catch (error) {
        console.error("Error initializing filters:", error);
        alert("⚠️ Failed to load page filters: " + error.message + "\n\nThe page may not function correctly. Please check your network connection and refresh the page.");
    }
}

function initSelect(selectID, values, preselectedValues) {
    if (values == null) {
        return;
    }
    select = document.getElementById(selectID);
    if (select != null) {
        // Parse preselected values if provided
        let preselectedArray = [];
        if (preselectedValues) {
            preselectedArray = preselectedValues.split(',').map(v => decodeURIComponent(v.trim()));
            console.log("Preselecting for " + selectID + ":", preselectedArray);
        }

        values.forEach(item => {
            //console.log(item)
            // Create a new row
            var option = document.createElement("option");

            // Set the text and value
            if(item == "") {
                option.text = "<none>";
            } else {
                option.text = item;
            }
            option.value = item;

            // Mark as selected if in preselected array
            if (preselectedArray.includes(item)) {
                option.selected = true;
                console.log("Pre-selected option: " + item);
            }

            // Add the option to the select element
            select.add(option);
        });
    }
}

async function getConfigProperty(property) {
    // Check if the property is already cached
    if (configCache[property] !== undefined) {
        console.log(`Cache hit for property: ${property}`);
        return configCache[property];
    }

    try {
        console.log("Fetching configuration from API...");
        const response = await fetch("/api/scannerconfig");

        // Check if the response is OK (status code 200)
        if (!response.ok) {
            throw new Error(`Failed to load configuration: ${response.status} ${response.statusText}`);
        }

        // Parse the JSON data from the response
        const data = await response.json();

        // Cache all the data properties
        Object.assign(configCache, data);
        return data[property];
    } catch (error) {
        console.error("Error loading configuration:", error);
        // Return default values for critical properties
        if (property === "scanContainers" || property === "scanNodes") {
            console.warn(`Defaulting ${property} to true due to error`);
            return true;
        }
        if (property === "clusterName") {
            return "Unknown Cluster";
        }
        throw error; // Re-throw for other properties
    }
}

async function showContainerScans() {
    property = await getConfigProperty("scanContainers");
    return Boolean(property);
}

async function showNodeScans() {
    property = await getConfigProperty("scanNodes");
    return Boolean(property);
}

// Shared sorting functionality
let currentSortField = null;
let currentSortDirection = "asc";

function addSortParameter(args, includeCSVOption) {
    // Add sort parameter if a field is selected (but not for CSV export)
    if (currentSortField && !includeCSVOption) {
        const sortValue = currentSortDirection === "desc" ? currentSortField + ".desc" : currentSortField;
        if (args === "") {
            args = "?sort=" + encodeURIComponent(sortValue);
        } else {
            args = args + "&sort=" + encodeURIComponent(sortValue);
        }
    }
    return args;
}

function sortByColumn(fieldName, reloadFunction, tableId) {
    // If clicking the same column, toggle direction
    if (currentSortField === fieldName) {
        currentSortDirection = currentSortDirection === "asc" ? "desc" : "asc";
    } else {
        // New column, start with ascending
        currentSortField = fieldName;
        currentSortDirection = "asc";
    }

    // Update visual indicators
    updateSortIndicators(tableId);

    // Reload table with new sort
    reloadFunction();
}

function updateSortIndicators(tableId) {
    // If tableId is provided, scope to that table only
    const scopeSelector = tableId ? `#${tableId} ` : "";

    // Remove all existing sort indicators in the specified table
    document.querySelectorAll(`${scopeSelector}.sortable`).forEach(th => {
        th.classList.remove("sort-asc", "sort-desc");
    });

    // Add indicator to current sorted column in the specified table
    if (currentSortField) {
        const headerElement = document.querySelector(`${scopeSelector}[data-sort-field="${currentSortField}"]`);
        if (headerElement) {
            headerElement.classList.add(currentSortDirection === "asc" ? "sort-asc" : "sort-desc");
        }
    }
}

function addSelectedItemsToArgument(currentArgument, selectId, urlArgument) {
    selectElement = document.getElementById(selectId);
    selectedValues = Array.from(selectElement.selectedOptions).map(option => option.value);
    if (selectedValues.length > 0) {
        commaSeparatedList = selectedValues.join(",");
        urlEncodedList = encodeURIComponent(commaSeparatedList);
        if(currentArgument == "") {
            return "?" + urlArgument + "=" + urlEncodedList;
        } else {
            return currentArgument + "&" + urlArgument + "=" + urlEncodedList;
        }
    } else {
        return currentArgument;
    }
}

function addCellToRow(toRow, align, text) {
    const cell = document.createElement("td");
    cell.innerHTML = text;
    cell.style.textAlign=align;
    toRow.appendChild(cell);
    return cell;
}

function toggleFilterVisible() {
    console.log("Starting");
    filterCell = document.getElementById("filterCell");
    console.log(filterCell.className);
    if (filterCell.className == "filterUnSelected") {
        // Show filters
        filterCell.className = "filterSelected";
        document.getElementById("filterContainer").className = "filterContainerSelected";
        document.getElementById("filterDetails").style.display = "table-row-group";
    } else {
        filterCell.className = "filterUnSelected";
        document.getElementById("filterContainer").className = "filterContainerUnSelected";
        document.getElementById("filterDetails").style.display = "none";
    }
}

// ========================================
// Backend Health Check & Connection Management
// ========================================

function createConnectionErrorOverlay() {
    // Check if overlay already exists
    if (document.getElementById("connectionErrorOverlay")) {
        return;
    }

    // Create overlay container
    const overlay = document.createElement("div");
    overlay.id = "connectionErrorOverlay";
    overlay.style.cssText = "display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0, 0, 0, 0.8); z-index: 10000; justify-content: center; align-items: center;";

    // Create content box
    const contentBox = document.createElement("div");
    contentBox.style.cssText = "background-color: white; padding: 40px; border-radius: 0px; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3); text-align: center; max-width: 500px;";

    // Loading icon
    const icon = document.createElement("div");
    icon.style.cssText = "font-size: 48px; margin-bottom: 20px;";
    icon.textContent = "⏳";

    // Title
    const title = document.createElement("h2");
    title.style.cssText = "margin-bottom: 15px;";
    title.textContent = "Application Starting...";

    // Description
    const description = document.createElement("p");
    description.style.cssText = "color: #666; font-size: 16px; margin-bottom: 20px;";
    description.textContent = "The backend is initializing. This usually takes a few seconds.";

    // Spinner container
    const spinnerContainer = document.createElement("div");
    spinnerContainer.style.cssText = "display: flex; align-items: center; justify-content: center; gap: 10px; color: #888;";

    // Spinner
    const spinner = document.createElement("div");
    spinner.className = "connection-spinner";
    spinner.style.cssText = "border: 3px solid #e0e0e0; border-top: 3px solid #333333; border-radius: 50%; width: 20px; height: 20px; animation: spin 1s linear infinite;";

    // Spinner text
    const spinnerText = document.createElement("span");
    spinnerText.textContent = "Please wait...";

    // Assemble components
    spinnerContainer.appendChild(spinner);
    spinnerContainer.appendChild(spinnerText);
    contentBox.appendChild(icon);
    contentBox.appendChild(title);
    contentBox.appendChild(description);
    contentBox.appendChild(spinnerContainer);
    overlay.appendChild(contentBox);

    // Add CSS animation for spinner
    const style = document.createElement("style");
    style.textContent = `
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    `;
    document.head.appendChild(style);

    // Add to body
    document.body.insertBefore(overlay, document.body.firstChild);
}

async function checkBackendHealth() {
    try {
        const response = await fetch("/api/hello", {
            method: 'GET',
            cache: 'no-cache'
        });
        return response.ok;
    } catch (error) {
        console.error("Backend health check failed:", error);
        return false;
    }
}

function showConnectionError() {
    const overlay = document.getElementById("connectionErrorOverlay");
    if (overlay) {
        overlay.style.display = "flex";
    }
}

function hideConnectionError() {
    const overlay = document.getElementById("connectionErrorOverlay");
    if (overlay) {
        overlay.style.display = "none";
    }
}

async function waitForBackend() {
    console.log("Checking backend availability...");

    let isHealthy = await checkBackendHealth();

    if (!isHealthy) {
        showConnectionError();

        // Poll every 2 seconds until backend is healthy
        return new Promise((resolve) => {
            const pollInterval = setInterval(async () => {
                console.log("Retrying backend health check...");
                isHealthy = await checkBackendHealth();

                if (isHealthy) {
                    console.log("Backend is now available!");
                    clearInterval(pollInterval);
                    hideConnectionError();
                    resolve();
                }
            }, 2000);
        });
    } else {
        console.log("Backend is available!");
        hideConnectionError();
    }
}

/**
 * Wrapper function to initialize a page with backend health check
 * Usage: waitForBackendAndInit(yourInitFunction);
 *
 * @param {Function} initFunction - The page initialization function to call after backend is ready
 */
async function waitForBackendAndInit(initFunction) {
    // Create the overlay element
    createConnectionErrorOverlay();

    // Wait for backend to be available
    await waitForBackend();

    // Call the provided init function
    if (typeof initFunction === 'function') {
        await initFunction();
    }
}

// ========================================
// Footer Initialization
// ========================================

function initAppFooter() {
    const footerContainer = document.getElementById("app-footer");
    if (!footerContainer) {
        return; // Footer container doesn't exist on this page
    }

    // Create footer content
    const version = window.BJORN2SCAN_VERSION || '';
    const versionText = version ? ` v${version}` : '';

    footerContainer.style.cssText = "text-align: right; text-decoration: underline; font-style: italic;";
    footerContainer.innerHTML = `<a href="https://github.com/bvboe/bjorn2scan/" target="_blank">Bjorn2Scan</a>${versionText}`;
}

// Initialize footer when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initAppFooter);
} else {
    initAppFooter();
}