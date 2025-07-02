function generateUrl(includeCSVOption) {
    const api = "/api/vulnsummary/image";
    args = "";
    if (includeCSVOption) {
        args = "?output=csv"
    }
    args = addSelectedItemsToArgument(args, "namespaceFilter", "namespace");
    args = addSelectedItemsToArgument(args, "vulnerabilityStatusFilter", "fixstatus");
    args = addSelectedItemsToArgument(args, "packageTypeFilter", "packagetype");
    return api + args;
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

async function loadContainerTable() {
    console.log("loadContainerTable()");
    url = generateUrl(false);
    console.log("Use URL: " + url)
    const response = await fetch(url);
    console.log("loadContainerTable() - Got data")
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

        //addCellToRow(newRow, "left", "<a href=\"image.html?imageid=" + item.image_id + "\">" + item.image + "</br>" + item.image_id + "</a");
        addCellToRow(newRow, "left", "<a href=\"image.html?imageid=" + item.image_id + "\">" + item.image + "</a");
        addCellToRow(newRow, "right", formatNumber(item.num_instances));
        switch(item.scan_status) {
            case "COMPLETE":
                addCellToRow(newRow, "right", formatNumber(item.vulnarbility_summary.critical));
                addCellToRow(newRow, "right", formatNumber(item.vulnarbility_summary.high));
                addCellToRow(newRow, "right", formatNumber(item.vulnarbility_summary.medium));
                addCellToRow(newRow, "right", formatNumber(item.vulnarbility_summary.low));
                addCellToRow(newRow, "right", formatNumber(item.vulnarbility_summary.negligible));
                addCellToRow(newRow, "right", formatNumber(item.vulnarbility_summary.unknown));
                addCellToRow(newRow, "right", formatNumber(item.vulnarbility_summary.total_risk));
                addCellToRow(newRow, "right", formatNumber(item.vulnarbility_summary.known_exploits));
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

function onFilterChange() {
    loadContainerTable();
    document.getElementById("csvlink").href = generateUrl(true);
}

$(function(){
    initFilters();
    loadContainerTable();
    renderSectionTable("images.html", null);
    document.getElementById("csvlink").href = generateUrl(true);
    initClusterName("Image Summary");
});
