function generateUrl(includeCSVOption) {
    const api = "/api/vulnsummary/cveii";
    args = "";
    if (includeCSVOption) {
        args = "?output=csv"
    }
    args = addSelectedItemsToArgument(args, "namespaceFilter", "namespace");
    args = addSelectedItemsToArgument(args, "vulnerabilityStatusFilter", "fixstatus");
    args = addSelectedItemsToArgument(args, "packageTypeFilter", "packagetype");
    args = addSelectedItemsToArgument(args, "vulnerabilitySeverityFilter", "severity");
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

async function loadCVEsTable() {
    console.log("loadCVEsTable()");
    url = generateUrl(false);
    console.log("Use URL: " + url)
    const response = await fetch(url);
    console.log("loadCVEsTable() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#cvesTable tbody");

    //Clear the table
    tableBody.replaceChildren();

    data.forEach(item => {
        console.log(item)
        // Create a new row
        const newRow = document.createElement("tr");
        addCellToRow(newRow, "left", item.vulnerability_severity);
        addCellToRow(newRow, "left", item.vulnerability_id);
        addCellToRow(newRow, "left", item.artifact_name);
        addCellToRow(newRow, "left", item.artifact_version);
        addCellToRow(newRow, "left", item.vulnerability_fix_versions);
        addCellToRow(newRow, "left", item.vulnerability_fix_state);
        addCellToRow(newRow, "left", item.artifact_type);
        addCellToRow(newRow, "right", formatNumber(item.image_count));

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
    loadCVEsTable();
    document.getElementById("csvlink").href = generateUrl(true);
}

$(function(){
    initFilters();
    loadCVEsTable();
    renderSectionTable("cves.html", null);
    document.getElementById("csvlink").href = generateUrl(true);
    initClusterName("Image CVE Summary");
});
