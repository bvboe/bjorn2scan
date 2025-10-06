function calculateAveragePerContainer(total, numberOfContainers) {
    if (numberOfContainers == 0) {
        return 0;
    } else {
        return (total / numberOfContainers);
    }
}

async function loadNamespaceSummaryTable(selectedNamespace) {
    // If no selectedNamespace provided, get it from URL parameters
    if (selectedNamespace === undefined) {
        const urlParams = new URLSearchParams(window.location.search);
        selectedNamespace = urlParams.get('namespace');
    }
    console.log("loadNamespaceSummaryTable(" + selectedNamespace + ")");
    if (!showContainerScans()) {
        return;
    }
    namespaceString="";
    if(selectedNamespace !== null) {
        console.log("Namespace is set");
        namespaceString = "?namespace="+selectedNamespace;
    }
    namespaceString = addSortParameter(namespaceString, false);
    url = "/api/image/summary" + namespaceString;
    console.log(url);
    const response = await fetch(url);
    console.log("loadNamespaceSummaryTable() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#namespaceSummaryTable tbody");

    //Clear the table
    tableBody.replaceChildren();

    rowCounter = 0;
    data.forEach(item => {
        rowCounter++;
        //console.log(item)
        // Create a new row
        const newRow = document.createElement("tr");
        newRow.classList.add("clickable-row");
        newRow.onclick = function() {
            window.location.href = "images.html?namespace=" + encodeURIComponent(item.namespace);
        };
        const scannedContainers = item.scanned_containers;
        addCellToRow(newRow, "left", item.namespace);
        addCellToRow(newRow, "right", formatNumber(scannedContainers));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_critical, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_high, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_medium, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_low, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_negligible, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_unknown, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_risk, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_known_exploits, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_number_of_packages, 0));

        // Append the new row to the table body
        tableBody.appendChild(newRow);
    });

    if(rowCounter == 0) {
        const newRow = document.createElement("tr");
        const newCell = addCellToRow(newRow, "left", "No Data Available");
        newCell.colSpan = 11;
        tableBody.appendChild(newRow);
    }
}

async function loadDistroTable(selectedNamespace) {
    // If no selectedNamespace provided, get it from URL parameters
    if (selectedNamespace === undefined) {
        const urlParams = new URLSearchParams(window.location.search);
        selectedNamespace = urlParams.get('namespace');
    }
    if (!showContainerScans()) {
        return;
    }
    console.log("loadDistroTable(" + selectedNamespace + ")");
    namespaceString="";
    if(selectedNamespace !== null) {
        console.log("Namespace is set");
        namespaceString = "?namespace="+selectedNamespace;
    }
    namespaceString = addSortParameter(namespaceString, false);
    url = "/api/distro/container-summary" + namespaceString;
    console.log("/api/distro/container-summary" + namespaceString);
    const response = await fetch(url);
    console.log("loadDistroTable() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#distroSummaryTable tbody");

    //Clear the table
    tableBody.replaceChildren();

    rowCounter = 0;
    data.forEach(item => {
        rowCounter++;
        //console.log(item)
        // Create a new row
        const newRow = document.createElement("tr");
        newRow.classList.add("clickable-row");
        newRow.onclick = function() {
            // Build URL with distribution filter and namespace if one was selected
            let url = "images.html?distributiondisplayname=" + encodeURIComponent(item.distro_display_name);
            if (selectedNamespace !== null) {
                url += "&namespace=" + encodeURIComponent(selectedNamespace);
            }
            window.location.href = url;
        };
        const scannedContainers = item.scanned_containers;
        addCellToRow(newRow, "left", item.distro_display_name);
        addCellToRow(newRow, "right", formatNumber(scannedContainers));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_critical, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_high, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_medium, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_low, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_negligible, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_unknown, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_risk, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_known_exploits, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_number_of_packages, 0));

        // Append the new row to the table body
        tableBody.appendChild(newRow);
    });

    if(rowCounter == 0) {
        const newRow = document.createElement("tr");
        const newCell = addCellToRow(newRow, "left", "No Data Available");
        newCell.colSpan = 11;
        tableBody.appendChild(newRow);
    }
}

async function loadNodeTable() {
    if (!showNodeScans()) {
        return;
    }
    console.log("loadNodeTable()");
    args = addSortParameter("", false);
    url = "/api/distro/node-summary" + args;
    console.log(url);
    const response = await fetch(url);
    console.log("loadDistroTable() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#nodeSummaryTable tbody");

    //Clear the table
    tableBody.replaceChildren();

    rowCounter = 0;
    data.forEach(item => {
        rowCounter++;
        //console.log(item)
        // Create a new row
        const newRow = document.createElement("tr");
        newRow.classList.add("clickable-row");
        newRow.onclick = function() {
            window.location.href = "nodes.html?distributiondisplayname=" + encodeURIComponent(item.distro_display_name);
        };
        const scannedNodes = item.scanned_nodes;
        addCellToRow(newRow, "left", item.distro_display_name);
        addCellToRow(newRow, "right", formatNumber(scannedNodes));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_critical, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_high, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_medium, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_low, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_negligible, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_cves_unknown, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_risk, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_known_exploits, 2));
        addCellToRow(newRow, "right", formatNumber(item.avg_number_of_packages, 0));

        // Append the new row to the table body
        tableBody.appendChild(newRow);
    });

    if(rowCounter == 0) {
        const newRow = document.createElement("tr");
        const newCell = addCellToRow(newRow, "left", "No Data Available");
        newCell.colSpan = 11;
        tableBody.appendChild(newRow);
    }
}

async function loadContainerScanStatus(selectedNamespace) {
    console.log("loadContainerScanStatus(" + selectedNamespace + ")");
    if (!showContainerScans()) {
        return;
    }
    namespaceString="";
    if(selectedNamespace !== null) {
        console.log("Namespace is set");
        namespaceString = "?namespace="+selectedNamespace;
    }
    const response = await fetch("/api/image/scanstatus" + namespaceString);
    console.log("loadContainerScanStatus() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#containerScanStatusTable tbody");
    tableBody.replaceChildren();

    addStatusTableRow(tableBody, "Scanning", data.SCANNING);
    addStatusTableRow(tableBody, "To Be Scanned", data.TO_BE_SCANNED);
    addStatusTableRow(tableBody, "Successfully Scanned", data.COMPLETE);
    addStatusTableRow(tableBody, "Failed", data.SCAN_FAILED);
    addStatusTableRow(tableBody, "Missing Scan Information", data.NO_SCAN_AVAILABLE);
}

async function loadNodeScanStatus() {
    console.log("loadNodeScanStatus()");
    if (!showNodeScans()) {
        return;
    }
    const response = await fetch("/api/node/scanstatus");
    console.log("loadNodeScanStatus() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#nodeScanStatusTable tbody");
    tableBody.replaceChildren();

    addStatusTableRow(tableBody, "Scanning", data.SCANNING);
    addStatusTableRow(tableBody, "To Be Scanned", data.TO_BE_SCANNED);
    addStatusTableRow(tableBody, "Successfully Scanned", data.COMPLETE);
    addStatusTableRow(tableBody, "Failed", data.SCAN_FAILED);
    addStatusTableRow(tableBody, "Missing Scan Information", data.NO_SCAN_AVAILABLE);
}

function addStatusTableRow(tableBody, status, count) {
    if(count == 0) {
        return;
    }
    const newRow = document.createElement("tr");
    const statusCell = document.createElement("td");
    statusCell.innerHTML = "<b>" + status + "</b>"
    newRow.appendChild(statusCell);
    const countCell = document.createElement("td");
    countCell.innerHTML = formatNumber(count);
    countCell.textAlign = "right";
    newRow.appendChild(countCell);
    tableBody.appendChild(newRow);
}

function addCellToRow(toRow, align, text) {
    const cell = document.createElement("td");
    cell.innerHTML = text;
    cell.style.textAlign = align;
    toRow.appendChild(cell);
    return cell;
}

function initCsvLink(selectedNamespace) {
    const namespaceCsvLink = document.getElementById("namespaceCsvlink");
    const distroCsvLink = document.getElementById("distroCsvlink");
    if(selectedNamespace !== null) {
        namespaceCsvLink.href = "/api/image/summary?output=csv&namespace=" + selectedNamespace;
        distroCsvLink.href = "/api/distro/container-summary?output=csv&namespace=" + selectedNamespace;
    } else {
        namespaceCsvLink.href = "/api/image/summary?output=csv"
        distroCsvLink.href = "/api/distro/container-summary?output=csv"
    }
}

async function hideSections() {
    const doShowContainerScans = await showContainerScans();
    const doShowNodeScans = await showNodeScans();
    if(!doShowContainerScans) {
        document.getElementById("containerScanStatus").style.display = "none";
        document.getElementById("namespaceSummary").style.display = "none";
        document.getElementById("distroSummary").style.display = "none";
    }
    if(!doShowNodeScans) {
        document.getElementById("nodeScanStatus").style.display = "none";
        document.getElementById("nodeSummary").style.display = "none";
    }
}

const urlParams = new URLSearchParams(window.location.search);
const namespace = urlParams.get('namespace');

renderSectionTable("index.html");
hideSections();
loadNamespaceSummaryTable(namespace);
loadDistroTable(namespace);
loadNodeTable();
loadContainerScanStatus(namespace);
loadNodeScanStatus();
loadNamespaceTable("index.html", namespace);
initCsvLink(namespace);
initClusterName("Vulnerability Summary");
