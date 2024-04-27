const { BigQuery } = require('@google-cloud/bigquery');
const { Storage } = require('@google-cloud/storage');
const csv = require('csv-parser');

exports.WriteToBigQuery = async (message, context) => {
    try {
        // Initialize BigQuery client
        const bigquery = new BigQuery();

        // Define BigQuery dataset and table
        const datasetId = 'vulnerability_report';
        const tableId = 'Reporting';

        // Initialize Storage client
        const storage = new Storage();

        // Define bucket name
        const bucketName = 'vulnerability_report'; // Remove gs:// prefix

        // Read data from CSV files in the bucket
        const [files] = await storage.bucket(bucketName).getFiles();

        // Object to store vulnerability counts for each asset
        const assetVulnerabilityCounts = {};

        for (const file of files) {
            const fileData = await file.createReadStream().pipe(csv()).toArray();
            fileData.forEach(row => {
                const assetName = row['DNS'];
                const ipAddress = row['IP']; // Extract IP address from the report
                if (!assetVulnerabilityCounts[assetName]) {
                    assetVulnerabilityCounts[assetName] = {
                        NumActive: 0,
                        NumNew: 0,
                        NumFixed: 0,
                        IpAddresses: new Set(), // Store unique IP addresses for each asset
                    };
                }

                if (ipAddress) { // Check if IP address is not null
                    assetVulnerabilityCounts[assetName].IpAddresses.add(ipAddress);
                }

                if (row['Vuln Status'] === 'Active' || row['Vuln Status'] === 'New') {
                    assetVulnerabilityCounts[assetName].NumActive++;
                    if (row['Vuln Status'] === 'New') {
                        assetVulnerabilityCounts[assetName].NumNew++;
                    }
                } else if (row['Vuln Status'] === 'Fixed') {
                    assetVulnerabilityCounts[assetName].NumFixed++;
                }
            });
        }

        // Update or insert data into BigQuery for each asset
        const dataset = bigquery.dataset(datasetId);

        for (const assetName in assetVulnerabilityCounts) {
            const { NumActive, NumNew, NumFixed, IpAddresses } = assetVulnerabilityCounts[assetName];
            const rowsToInsert = Array.from(IpAddresses).map(ipAddress => ({
                IPAddress: ipAddress,
                AssetName: assetName,
                NumVulnerabilitiesPresent: NumActive + NumFixed,
                NumPreviouslyDiscovered: NumActive - NumNew,
                NumNewlyDiscovered: NumNew,
                NumRemediated: NumFixed,
            }));

            // Check if the asset already exists in the table
            const table = dataset.table(tableId);
            const query = `SELECT * FROM ${datasetId}.${tableId} WHERE AssetName='${assetName}'`;
            const [rows] = await bigquery.query(query);

            if (rows && rows.length > 0) {
                // Compare the existing rows with the new rows
                const existingRows = rows.map(row => ({
                    IPAddress: row.IPAddress,
                    AssetName: row.AssetName,
                    NumVulnerabilitiesPresent: row.NumVulnerabilitiesPresent,
                    NumPreviouslyDiscovered: row.NumPreviouslyDiscovered,
                    NumNewlyDiscovered: row.NumNewlyDiscovered,
                    NumRemediated: row.NumRemediated,
                }));

                const updatedRows = rowsToInsert.filter(newRow => {
                    const existingRow = existingRows.find(row => row.IPAddress === newRow.IPAddress);
                    if (!existingRow) return true; // Insert new row if it doesn't exist
                    return !isEqual(existingRow, newRow); // Update row if there are differences
                });

                if (updatedRows.length > 0) {
                    // Update the existing rows
                    await table.insert(updatedRows);
                }
            } else {
                // Insert new rows
                await table.insert(rowsToInsert);
            }
        }

        console.log('Data successfully inserted or updated in BigQuery.');

    } catch (error) {
        console.error('Error writing data to BigQuery:', error);
    }
};

// Function to check if two objects are equal
function isEqual(obj1, obj2) {
    const keys1 = Object.keys(obj1);
    const keys2 = Object.keys(obj2);

    if (keys1.length !== keys2.length) {
        return false;
    }

    for (const key of keys1) {
        if (obj1[key] !== obj2[key]) {
            return false;
        }
    }

    return true;
}
