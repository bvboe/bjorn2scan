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
        const response = await fetch("/api/node/vulnerabilities?nodename=" + nodename);
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
            linkRef = "<a href=\"#\" onclick=\"toggleDetailsTableRow(\'" + vulnCellId + "\', this.dataset.url); return false;\" data-url=" + item.details_url + ">";

            addCellToRow(newRow, "left", linkRef + item.vulnerability_severity + "</a>");
            addCellToRow(newRow, "left", linkRef + item.vulnerability_id + "</a>");
            addCellToRow(newRow, "left", linkRef + item.artifact_name + "</a>");
            addCellToRow(newRow, "left", linkRef + item.artifact_version + "</a>");
            addCellToRow(newRow, "left", linkRef + item.vulnerability_fix_versions + "</a>");
            addCellToRow(newRow, "left", linkRef + item.vulnerability_fix_state + "</a>");
            addCellToRow(newRow, "left", linkRef + item.artifact_type + "</a>");
            addCellToRow(newRow, "right", linkRef + formatRiskNumber(item.vulnerability_risk) + "</a>");
            addCellToRow(newRow, "right", linkRef + item.vulnerability_known_exploits + "</a>");

    
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
        const response = await fetch("/api/node/sbom?nodename=" + nodename);
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
            linkRef = "<a href=\"#\" onclick=\"toggleDetailsTableRow(\'" + sbomCellId + "\', this.dataset.url); return false;\" data-url=" + item.details_url + ">";
            addCellToRow(newRow, "left", linkRef + item.name + "</a>");
            addCellToRow(newRow, "left", linkRef + item.version + "</a>");
            addCellToRow(newRow, "left", linkRef + item.type + "</a>");
            addCellToRow(newRow, "right", linkRef + item.count + "</a>");

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

function addCellToRow(toRow, align, text) {
    const cell = document.createElement("td");
    cell.innerHTML = text;
    cell.style.textAlign=align;
    toRow.appendChild(cell);
    return cell;
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

const urlParams = new URLSearchParams(window.location.search);
const nodename = urlParams.get('nodename');

loadNodeDetails(nodename);
document.getElementById("cvecsvlink").href = "/api/node/vulnerabilities?output=csv&nodename=" + nodename;
document.getElementById("cvejsonlink").href = "/api/node/vulnerabilities?output=json&nodename=" + nodename;
document.getElementById("sbomcsvlink").href = "/api/node/sbom?output=csv&nodename=" + nodename;
document.getElementById("sbomjsonlink").href = "/api/node/sbom?output=json&nodename=" + nodename;
