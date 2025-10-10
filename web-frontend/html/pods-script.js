function generateUrl(includeCSVOption) {
    const api = "/api/vulnsummary/pod";
    args = "";
    if (includeCSVOption) {
        args = "?output=csv"
    }
    args = addSelectedItemsToArgument(args, "namespaceFilter", "namespace");
    args = addSelectedItemsToArgument(args, "vulnerabilityStatusFilter", "fixstatus");
    args = addSelectedItemsToArgument(args, "packageTypeFilter", "packagetype");
    args = addSelectedItemsToArgument(args, "distributionDisplayNameFilter", "distributiondisplayname");
    args = addSortParameter(args, includeCSVOption);
    return api + args;
}

async function loadPodsTable() {
    console.log("loadPodsTable()");
    const tableBody = document.querySelector("#podsTable tbody");

    try {
        url = generateUrl(false);
        console.log("Use URL: " + url)
        const response = await fetch(url);
        console.log("loadPodsTable() - Got data")
        // Check if the response is OK (status code 200)
        if (!response.ok) {
            throw new Error(`Failed to load pod data: ${response.status} ${response.statusText}`);
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
                window.location.href = "image.html?imageid=" + item.image_id;
            };

            addCellToRow(newRow, "left", item.namespace);
            addCellToRow(newRow, "left", item.pod_name);
            addCellToRow(newRow, "left", item.container_name);

            switch(item.scan_status) {
                case "COMPLETE":
                    addCellToRow(newRow, "right", formatNumber(item.cves_critical));
                    addCellToRow(newRow, "right", formatNumber(item.cves_high));
                    addCellToRow(newRow, "right", formatNumber(item.cves_medium));
                    addCellToRow(newRow, "right", formatNumber(item.cves_low));
                    addCellToRow(newRow, "right", formatNumber(item.cves_negligible));
                    addCellToRow(newRow, "right", formatNumber(item.cves_unknown));
                    addCellToRow(newRow, "right", formatNumber(item.total_risk));
                    addCellToRow(newRow, "right", formatNumber(item.known_exploits));
                    addCellToRow(newRow, "right", formatNumber(item.number_of_packages));
                    break;
                case "SCANNING":
                    newCell = addCellToRow(newRow, "left", "Scanning");
                    newCell.colSpan = 9;
                    break;
                case "TO_BE_SCANNED":
                    newCell = addCellToRow(newRow, "left", "To be scanned");
                    newCell.colSpan = 9;
                    break;
                case "NO_SCAN_AVAILABLE":
                    newCell = addCellToRow(newRow, "left", "No scan information");
                    newCell.colSpan = 9;
                    break;
                case "SCAN_FAILED":
                    newCell = addCellToRow(newRow, "left", "Scan failed");
                    newCell.colSpan = 9;
                    break;
                default:
                  // code block
              }

            // Append the new row to the table body
            tableBody.appendChild(newRow);
        });
    } catch (error) {
        console.error("Error loading pod data:", error);
        tableBody.replaceChildren();
        const newRow = document.createElement("tr");
        const newCell = addCellToRow(newRow, "left", "⚠️ Error loading data: " + error.message);
        newCell.colSpan = 12;
        newCell.style.color = "red";
        tableBody.appendChild(newRow);
    }
}

function onFilterChange() {
    loadPodsTable();
    document.getElementById("csvlink").href = generateUrl(true);
    renderSectionTable("pods.html");
}

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
        namespaceFilter: urlParams.get('namespace'),
        vulnerabilityStatusFilter: urlParams.get('fixstatus'),
        packageTypeFilter: urlParams.get('packagetype'),
        distributionDisplayNameFilter: urlParams.get('distributiondisplayname')
    };

    // Pass URL filters to initFilters so options can be pre-selected
    await initFilters(urlFilters);

    loadPodsTable();
    renderSectionTable("pods.html");
    document.getElementById("csvlink").href = generateUrl(true);
    initClusterName("Pod Summary");

    // Start polling for updates every 2 seconds
    setInterval(checkForUpdates, 2000);
}

$(function(){
    waitForBackendAndInit(initPage);
});

