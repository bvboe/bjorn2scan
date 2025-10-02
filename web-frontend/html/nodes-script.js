function generateUrl(includeCSVOption) {
    const api = "/api/vulnsummary/nodeii";
    args = "";
    if (includeCSVOption) {
        args = "?output=csv"
    }
    args = addSelectedItemsToArgument(args, "vulnerabilityStatusFilter", "fixstatus");
    args = addSelectedItemsToArgument(args, "packageTypeFilter", "packagetype");
    args = addSortParameter(args, includeCSVOption);
    return api + args;
}

async function loadNodeTable() {
    console.log("loadNodeTable()");
    url = generateUrl(false);
    console.log("Use URL: " + url)
    const response = await fetch(url);
    console.log("loadNodeTable() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#vulnerabilityTable tbody");

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
                addCellToRow(newRow, "right", formatNumber(item.total_risk));
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
}

function onFilterChange() {
    loadNodeTable();
    document.getElementById("csvlink").href = generateUrl(true);
}

$(function(){
    initFilters();
    loadNodeTable();
    renderSectionTable("nodes.html", null);
    document.getElementById("csvlink").href = generateUrl(true);
    initClusterName("Node Summary");
});
