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
    args = addSelectedItemsToArgument(args, "distributionDisplayNameFilter", "distributiondisplayname");
    args = addSortParameter(args, includeCSVOption);
    return api + args;
}

async function loadCVEsTable() {
    console.log("loadCVEsTable()");
    const tableBody = document.querySelector("#cvesTable tbody");

    try {
        url = generateUrl(false);
        console.log("Use URL: " + url)
        const response = await fetch(url);
        console.log("loadCVEsTable() - Got data")
        // Check if the response is OK (status code 200)
        if (!response.ok) {
            throw new Error(`Failed to load CVE data: ${response.status} ${response.statusText}`);
        }

        // Parse the JSON data from the response
        const data = await response.json();

        //Clear the table
        tableBody.replaceChildren();

        data.forEach(item => {
            //console.log(item)
            // Create a new row
            const newRow = document.createElement("tr");
            addCellToRow(newRow, "left", item.vulnerability_severity);
            addCellToRow(newRow, "left", item.vulnerability_id);
            addCellToRow(newRow, "left", item.artifact_name);
            addCellToRow(newRow, "left", item.artifact_version);
            addCellToRow(newRow, "left", item.vulnerability_fix_versions);
            addCellToRow(newRow, "left", item.vulnerability_fix_state);
            addCellToRow(newRow, "left", item.artifact_type);
            addCellToRow(newRow, "right", formatNumber(item.vulnerability_known_exploits));
            addCellToRow(newRow, "right", formatRiskNumber(item.vulnerability_risk));
            addCellToRow(newRow, "right", formatNumber(item.image_count));

            // Append the new row to the table body
            tableBody.appendChild(newRow);
        });
    } catch (error) {
        console.error("Error loading CVE data:", error);
        tableBody.replaceChildren();
        const newRow = document.createElement("tr");
        const newCell = addCellToRow(newRow, "left", "⚠️ Error loading data: " + error.message);
        newCell.colSpan = 10;
        newCell.style.color = "red";
        tableBody.appendChild(newRow);
    }
}

function formatRiskNumber(risk) {
    if (risk < 0.1) {
        return "< 0.1";
    }
    return risk.toFixed(1);
}

function onFilterChange() {
    loadCVEsTable();
    document.getElementById("csvlink").href = generateUrl(true);
    renderSectionTable("cves.html");
}

async function initPage() {
    // Check for URL parameters BEFORE initializing filters
    const urlParams = new URLSearchParams(window.location.search);
    const urlFilters = {
        namespaceFilter: urlParams.get('namespace'),
        vulnerabilityStatusFilter: urlParams.get('fixstatus'),
        packageTypeFilter: urlParams.get('packagetype'),
        vulnerabilitySeverityFilter: urlParams.get('severity'),
        distributionDisplayNameFilter: urlParams.get('distributiondisplayname')
    };

    // Pass URL filters to initFilters so options can be pre-selected
    await initFilters(urlFilters);

    loadCVEsTable();
    renderSectionTable("cves.html");
    document.getElementById("csvlink").href = generateUrl(true);
    initClusterName("Image CVE Summary");
}

$(function(){
    waitForBackendAndInit(initPage);
});
