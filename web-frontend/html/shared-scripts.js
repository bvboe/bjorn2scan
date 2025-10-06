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

    addNamespaceSelect(select, "All Namespaces", currentUrl, currentNamespace, false);
    addNamespaceSelect(select, "─────", currentUrl, currentNamespace, true);
    data.forEach(item => {
        addNamespaceSelect(select, item, currentUrl + "?namespace=" + item, currentNamespace, false);
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

function doRenderHeaderCell(tableBody, title, url, currentUrl, currentNamespace) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    if(currentNamespace == null) {
        fullUrl = url;
    } else {
        fullUrl = url + "?namespace=" + currentNamespace;
    }
    if(currentUrl == url) {
        decorationFront="<u>"
        decorationEnd="</u>"
    } else {
        decorationFront=""
        decorationEnd=""
    }
    cell.innerHTML = "<h2><a href=\"" + fullUrl + "\">" + decorationFront + title + decorationEnd + "</a></h2>";
    //cell.innerHTML = "<a href=\"" + fullUrl + "\">" + decorationFront + title + decorationEnd + "</a>";
    row.appendChild(cell);
    tableBody.appendChild(row);
}

async function renderSectionTable(currentUrl, currentNamespace) {
    const tableBody = document.querySelector("#headerTable tbody");
    tableBody.replaceChildren();

    const doShowContainerScans = await showContainerScans();
    const doShowNodeScans = await showNodeScans();
    console.log("container scans - " + doShowContainerScans);
    console.log("node scans - " + doShowNodeScans);
    
    doRenderHeaderCell(tableBody, "Summary", "index.html", currentUrl, currentNamespace);
    if (doShowContainerScans) {
        doRenderHeaderCell(tableBody, "Images", "images.html", currentUrl, currentNamespace);
        doRenderHeaderCell(tableBody, "Pods", "pods.html", currentUrl, currentNamespace);
    }
    if (doShowNodeScans) { 
        doRenderHeaderCell(tableBody, "Nodes", "nodes.html", currentUrl, currentNamespace);
    }
    if (doShowContainerScans) {
        doRenderHeaderCell(tableBody, "CVEs", "cves.html", currentUrl, currentNamespace);
        doRenderHeaderCell(tableBody, "SBOM", "sbom.html", currentUrl, currentNamespace);
    }
}

function formatNumber(num, digits = 0) {
    return num.toLocaleString('en-US', { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

function onNamespaceChange(selectedNamespace) {
    window.location.href = selectedNamespace;
}

async function initClusterName(pageTitle) {
    console.log("initClusterName()");
    const clusterName = await getConfigProperty("clusterName")
    const clusternameDiv = document.getElementById("clusterName");
    clusternameDiv.innerText = pageTitle + " - " + clusterName;
}

async function initFilters() {
    const response = await fetch("/api/filters");
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }
    const filterData = await response.json();
    initSelect("namespaceFilter", filterData.namespaces);
    initSelect("vulnerabilityStatusFilter", filterData['fix-states']);
    initSelect("packageTypeFilter", filterData['unique-packages']);
    initSelect("vulnerabilitySeverityFilter", filterData['severities']);
    initSelect("distributionDisplayNameFilter", filterData['distribution-display-names']);
    
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
}

function initSelect(selectID, values) {
    if (values == null) {
        return;
    }
    select = document.getElementById(selectID);
    if (select != null) {
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

    console.log("Fetching configuration from API...");
    const response = await fetch("/api/scannerconfig");

    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Cache all the data properties
    Object.assign(configCache, data);
    return data[property];
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