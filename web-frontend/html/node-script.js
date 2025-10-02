// Separate sort state for each table on this page
let cveSortField = null;
let cveSortDirection = "asc";
let sbomSortField = null;
let sbomSortDirection = "asc";

async function loadNodeDetails(nodename) {
    console.log("loadNodeDetails(" + nodename + ")");
    if(nodename == null) {
        console.log("No node, returning");
        return;
    }

    console.log("/api/node/details?nodename=" + nodename);
    const response = await fetch("/api/node/details?nodename=" + nodename);
    console.log("loadNodeSummary() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();
    document.querySelector("#node_name").innerHTML = data.node_name;

    scan_status_description = "";
    switch(data.scan_status) {
        case "COMPLETE":
            scan_status_description = "Complete";
            break;
        case "SCANNING":
            scan_status_description = "Scanning";
            break;
        case "TO_BE_SCANNED":
            scan_status_description = "To be scanned";
            break;
        case "NO_SCAN_AVAILABLE":
            scan_status_description = "No scan information";
            break;
        case "SCAN_FAILED":
            scan_status_description = "Scan failed";
            break;
        default:
            scan_status_description = data.scan_status;
            // code block
      }

    document.querySelector("#scan_status").innerHTML = scan_status_description;

    distro_name = data.distro_name;
    document.querySelector("#distro_name").innerHTML = distro_name;

    loadCVEsTable(nodename, data.scan_status);
    loadSBOMTable(nodename, data.scan_status);
}

async function loadCVEsTable(nodename, scanStatus) {
    console.log("loadCVEsTable(" + nodename + ")");
    if(nodename == null) {
        console.log("No node, returning");
        return;
    }

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#cvesTable tbody");

    //Clear the table
    tableBody.replaceChildren();

    if(scanStatus == "COMPLETE") {
        url = "/api/node/vulnerabilities?nodename=" + nodename;
        // Add sort parameter
        if (cveSortField) {
            const sortValue = cveSortDirection === "desc" ? cveSortField + ".desc" : cveSortField;
            url += "&sort=" + encodeURIComponent(sortValue);
        }
        const response = await fetch(url);
        console.log("loadCVEsTable() - Got data")
        // Check if the response is OK (status code 200)
        if (!response.ok) {
            throw new Error("Network response was not ok");
        }
    
        // Parse the JSON data from the response
        const data = await response.json();
        counter = 0;

        data.forEach(item => {
            //console.log(item)
            vulnCellId = "vulncell"+counter;
            // Create a new row
            const newRow = document.createElement("tr");
            newRow.classList.add("clickable-row");
            newRow.dataset.detailsUrl = item.details_url;
            newRow.dataset.detailCellId = vulnCellId;
            newRow.onclick = function() {
                toggleDetailsTableRow(this.dataset.detailCellId, this.dataset.detailsUrl);
            };

            addCellToRow(newRow, "left", item.vulnerability_severity);
            addCellToRow(newRow, "left", item.vulnerability_id);
            addCellToRow(newRow, "left", item.artifact_name);
            addCellToRow(newRow, "left", item.artifact_version);
            addCellToRow(newRow, "left", item.vulnerability_fix_versions);
            addCellToRow(newRow, "left", item.vulnerability_fix_state);
            addCellToRow(newRow, "left", item.artifact_type);
            addCellToRow(newRow, "right", formatRiskNumber(item.vulnerability_risk));
            addCellToRow(newRow, "right", item.vulnerability_known_exploits);

            // Append the new row to the table body
            tableBody.appendChild(newRow);

            const vulnRow = document.createElement("tr");
            const vulnCell = document.createElement("td");
            vulnCell.colSpan = 9;
            vulnCell.id = vulnCellId;
            vulnCell.hidden = true;

            vulnRow.appendChild(vulnCell);
            tableBody.appendChild(vulnRow);
            counter++;
        });
    } else {
        const newRow = document.createElement("tr");
        const newCell = addCellToRow(newRow, "left", "Vulnerability data missing");
        newCell.colSpan = 9;
        tableBody.appendChild(newRow);
    }
}

function formatRiskNumber(risk) {
    if (risk < 0.1) {
        return "< 0.1";
    }
    return risk.toFixed(1);
}

async function toggleDetailsTableRow(cellId, detailsUrl) {
    const cell = document.querySelector("#" + cellId);
    if (cell.hidden == false) {
        cell.hidden = true;
        cell.innerHTML = "";
    } else {
        cell.hidden = false;
        try {
            const response = await fetch(detailsUrl);
            if (!response.ok) {
                throw new Error("Network response was not ok");
            }
            const data = await response.json();
            cell.innerHTML = "<pre>" + JSON.stringify(data, null, 2) + "</pre>";
        } catch (error) {
            cell.innerHTML = "<span style='color: red;'>Failed to load details: " + error.message + "</span>";
        }
    }
}

async function loadSBOMTable(nodename, scanStatus) {
    console.log("loadSBOMTable(" + nodename + ")");
    if(nodename == null) {
        console.log("No node, returning");
        return;
    }

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#sbomTable tbody");

    //Clear the table
    tableBody.replaceChildren();

    if(scanStatus == "COMPLETE") {
        url = "/api/node/sbom?nodename=" + nodename;
        // Add sort parameter
        if (sbomSortField) {
            const sortValue = sbomSortDirection === "desc" ? sbomSortField + ".desc" : sbomSortField;
            url += "&sort=" + encodeURIComponent(sortValue);
        }
        const response = await fetch(url);
        console.log("loadSBOMTable() - Got data")
        // Check if the response is OK (status code 200)
        if (!response.ok) {
            throw new Error("Network response was not ok");
        }

        // Parse the JSON data from the response
        const data = await response.json();
        counter = 0;

        data.forEach(item => {
            //console.log(item)
            sbomCellId = "sbomcell"+counter;
            // Create a new row
            const newRow = document.createElement("tr");
            newRow.classList.add("clickable-row");
            newRow.dataset.detailsUrl = item.details_url;
            newRow.dataset.detailCellId = sbomCellId;
            newRow.onclick = function() {
                toggleDetailsTableRow(this.dataset.detailCellId, this.dataset.detailsUrl);
            };

            addCellToRow(newRow, "left", item.name);
            addCellToRow(newRow, "left", item.version);
            addCellToRow(newRow, "left", item.type);
            addCellToRow(newRow, "right", item.count);

            // Append the new row to the table body
            tableBody.appendChild(newRow);

            const sbomRow = document.createElement("tr");
            const sbomCell = document.createElement("td");
            sbomCell.colSpan = 4;
            sbomCell.id = sbomCellId;
            sbomCell.hidden = true;

            sbomRow.appendChild(sbomCell);
            tableBody.appendChild(sbomRow);
            counter++;
        });
    } else {
        const newRow = document.createElement("tr");
        const newCell = addCellToRow(newRow, "left", "SBOM missing");
        newCell.colSpan = 4;
        tableBody.appendChild(newRow);
    }
}

function showVulnerabilityTable() {
    document.querySelector("#cvesSection").style.display = "block";
    document.querySelector("#sbomSection").style.display = "none";
    document.querySelector("#cvesHeader").style.textDecoration = "underline";
    document.querySelector("#sbomHeader").style.textDecoration = "none";
}

function showSBOMTable() {
    document.querySelector("#cvesSection").style.display = "none";
    document.querySelector("#sbomSection").style.display = "block";
    document.querySelector("#cvesHeader").style.textDecoration = "none";
    document.querySelector("#sbomHeader").style.textDecoration = "underline";
}

function sortCVEsByColumn(fieldName) {
    // If clicking the same column, toggle direction
    if (cveSortField === fieldName) {
        cveSortDirection = cveSortDirection === "asc" ? "desc" : "asc";
    } else {
        // New column, start with ascending
        cveSortField = fieldName;
        cveSortDirection = "asc";
    }

    // Update visual indicators
    updateCVESortIndicators();

    // Reload table with new sort
    const urlParams = new URLSearchParams(window.location.search);
    const nodename = urlParams.get('nodename');
    loadCVEsTable(nodename, "COMPLETE");
}

function updateCVESortIndicators() {
    // Remove all existing sort indicators from CVE table
    document.querySelectorAll("#cvesTable .sortable").forEach(th => {
        th.classList.remove("sort-asc", "sort-desc");
    });

    // Add indicator to current sorted column
    if (cveSortField) {
        const headerElement = document.querySelector(`#cvesTable [data-sort-field="${cveSortField}"]`);
        if (headerElement) {
            headerElement.classList.add(cveSortDirection === "asc" ? "sort-asc" : "sort-desc");
        }
    }
}

function sortSBOMByColumn(fieldName) {
    // If clicking the same column, toggle direction
    if (sbomSortField === fieldName) {
        sbomSortDirection = sbomSortDirection === "asc" ? "desc" : "asc";
    } else {
        // New column, start with ascending
        sbomSortField = fieldName;
        sbomSortDirection = "asc";
    }

    // Update visual indicators
    updateSBOMSortIndicators();

    // Reload table with new sort
    const urlParams = new URLSearchParams(window.location.search);
    const nodename = urlParams.get('nodename');
    loadSBOMTable(nodename, "COMPLETE");
}

function updateSBOMSortIndicators() {
    // Remove all existing sort indicators from SBOM table
    document.querySelectorAll("#sbomTable .sortable").forEach(th => {
        th.classList.remove("sort-asc", "sort-desc");
    });

    // Add indicator to current sorted column
    if (sbomSortField) {
        const headerElement = document.querySelector(`#sbomTable [data-sort-field="${sbomSortField}"]`);
        if (headerElement) {
            headerElement.classList.add(sbomSortDirection === "asc" ? "sort-asc" : "sort-desc");
        }
    }
}

const urlParams = new URLSearchParams(window.location.search);
const nodename = urlParams.get('nodename');

loadNodeDetails(nodename);
document.getElementById("cvecsvlink").href = "/api/node/vulnerabilities?output=csv&nodename=" + nodename;
document.getElementById("cvejsonlink").href = "/api/node/vulnerabilities?output=json&nodename=" + nodename;
document.getElementById("sbomcsvlink").href = "/api/node/sbom?output=csv&nodename=" + nodename;
document.getElementById("sbomjsonlink").href = "/api/node/sbom?output=json&nodename=" + nodename;
