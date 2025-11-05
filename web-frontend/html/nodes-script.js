function generateUrl(includeCSVOption) {
    const api = "/api/vulnsummary/nodeii";
    args = "";
    if (includeCSVOption) {
        args = "?output=csv"
    }
    args = addSelectedItemsToArgument(args, "vulnerabilityStatusFilter", "fixstatus");
    args = addSelectedItemsToArgument(args, "packageTypeFilter", "packagetype");
    args = addSelectedItemsToArgument(args, "distributionDisplayNameFilter", "distributiondisplayname");
    args = addSortParameter(args, includeCSVOption);
    return api + args;
}

async function loadNodeTable() {
    console.log("loadNodeTable()");
    const tableBody = document.querySelector("#vulnerabilityTable tbody");

    try {
        url = generateUrl(false);
        console.log("Use URL: " + url)
        const response = await fetch(url);
        console.log("loadNodeTable() - Got data")
        // Check if the response is OK (status code 200)
        if (!response.ok) {
            throw new Error(`Failed to load node data: ${response.status} ${response.statusText}`);
        }

        // Parse the JSON data from the response
        const data = await response.json();

        //Clear the table
        tableBody.replaceChildren();

        data.forEach(item => {
            //console.log(item)
            // Create a new row
            const newRow = document.createElement("tr");
            newRow.classList.add("clickable-row");
            newRow.onclick = function() {
                window.location.href = "node.html?nodename=" + item.node_name;
            };

            addCellToRow(newRow, "left", item.node_name);
            switch(item.scan_status) {
                case "COMPLETE":
                    addCellToRow(newRow, "left", item.distro_name + " (" + item.distro_id + ")");
                    addCellToRow(newRow, "right", formatNumber(item.cves_critical));
                    addCellToRow(newRow, "right", formatNumber(item.cves_high));
                    addCellToRow(newRow, "right", formatNumber(item.cves_medium));
                    addCellToRow(newRow, "right", formatNumber(item.cves_low));
                    addCellToRow(newRow, "right", formatNumber(item.cves_negligible));
                    addCellToRow(newRow, "right", formatNumber(item.cves_unknown));
                    addCellToRow(newRow, "right", formatRiskNumber(item.total_risk));
                    addCellToRow(newRow, "right", formatNumber(item.known_exploits));
                    addCellToRow(newRow, "right", formatNumber(item.number_of_packages));
                    break;
                case "SCANNING":
                    newCell = addCellToRow(newRow, "left", "Scanning");
                    newCell.colSpan = 10;
                    break;
                case "TO_BE_SCANNED":
                    newCell = addCellToRow(newRow, "left", "To be scanned");
                    newCell.colSpan = 10;
                    break;
                case "NO_SCAN_AVAILABLE":
                    newCell = addCellToRow(newRow, "left", "No scan information");
                    newCell.colSpan = 10;
                    break;
                case "SCAN_FAILED":
                    newCell = addCellToRow(newRow, "left", "Scan failed");
                    newCell.colSpan = 10;
                    break;
                default:
                  // code block
              }

            // Append the new row to the table body
            tableBody.appendChild(newRow);
        });
    } catch (error) {
        console.error("Error loading node data:", error);
        tableBody.replaceChildren();
        const newRow = document.createElement("tr");
        const newCell = addCellToRow(newRow, "left", "⚠️ Error loading data: " + error.message);
        newCell.colSpan = 11;
        newCell.style.color = "red";
        tableBody.appendChild(newRow);
    }
}

function onFilterChange() {
    loadNodeTable();
    document.getElementById("csvlink").href = generateUrl(true);
    renderSectionTable("nodes.html");
}

let currentTimestamp = null;

async function checkForUpdates() {
    try {
        const response = await fetch("/api/lastupdated?datatype=node");
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
            onFilterChange();
        }
    } catch (error) {
        console.error("Error checking for updates:", error);
    }
}

async function initPage() {
    // Check for URL parameters BEFORE initializing filters
    const urlParams = new URLSearchParams(window.location.search);
    const urlFilters = {
        vulnerabilityStatusFilter: urlParams.get('fixstatus'),
        packageTypeFilter: urlParams.get('packagetype'),
        distributionDisplayNameFilter: urlParams.get('distributiondisplayname')
    };

    // Pass URL filters to initFilters so options can be pre-selected
    await initFilters(urlFilters);

    loadNodeTable();
    renderSectionTable("nodes.html");
    document.getElementById("csvlink").href = generateUrl(true);
    initClusterName("Node Summary");

    // Start polling for updates every 2 seconds
    setInterval(checkForUpdates, 2000);
}

$(function(){
    waitForBackendAndInit(initPage);
});
