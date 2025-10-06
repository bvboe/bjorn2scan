function generateUrl(includeCSVOption) {
    const api = "/api/sbomsummaryii";
    args = "";
    if (includeCSVOption) {
        args = "?output=csv"
    }
    args = addSelectedItemsToArgument(args, "namespaceFilter", "namespace");
    args = addSelectedItemsToArgument(args, "packageTypeFilter", "packagetype");
    args = addSelectedItemsToArgument(args, "distributionDisplayNameFilter", "distributiondisplayname");
    args = addSortParameter(args, includeCSVOption);
    return api + args;
}

async function loadSBOMTable() {
    console.log("loadSBOMTable()");
    url = generateUrl(false);
    console.log(url)
    const response = await fetch(url);
    console.log("loadSBOMTable() - Got data")
    // Check if the response is OK (status code 200)
    if (!response.ok) {
        throw new Error("Network response was not ok");
    }

    // Parse the JSON data from the response
    const data = await response.json();

    // Get the table body element where rows will be added
    const tableBody = document.querySelector("#sbomTable tbody");

    //Clear the table
    tableBody.replaceChildren();

    data.forEach(item => {
        //console.log(item)
        // Create a new row
        const newRow = document.createElement("tr");
        addCellToRow(newRow, "left", item.name);
        addCellToRow(newRow, "left", item.version);
        addCellToRow(newRow, "left", item.type);
        addCellToRow(newRow, "right", formatNumber(item.image_count));

        // Append the new row to the table body
        tableBody.appendChild(newRow);
    });
}

function onFilterChange() {
    loadSBOMTable();
    document.getElementById("csvlink").href = generateUrl(true);
}

async function initPage() {
    // Check for URL parameters BEFORE initializing filters
    const urlParams = new URLSearchParams(window.location.search);
    const urlFilters = {
        namespaceFilter: urlParams.get('namespace'),
        packageTypeFilter: urlParams.get('packagetype'),
        distributionDisplayNameFilter: urlParams.get('distributiondisplayname')
    };

    // Pass URL filters to initFilters so options can be pre-selected
    await initFilters(urlFilters);

    loadSBOMTable();
    renderSectionTable("sbom.html", null);
    document.getElementById("csvlink").href = generateUrl(true);
    initClusterName("Image Software Bill of Materials");
}

$(function(){
    initPage();
});
