const { BigQuery } = require('@google-cloud/bigquery');
const { Storage } = require('@google-cloud/storage');
const csv = require('csv-parser');

exports.WriteToBigQuery = async (message, context) => {
    try {

        const bigquery = new BigQuery();
        const datasetId = 'vulnerability_report';
        const tableId = 'Reporting';
        const storage = new Storage();
        const bucketName = 'gs://vulnerability_report';
        const [files] = await storage.bucket(bucketName).getFiles();
        const assetVulnerabilityCounts = {};

        for (const file of files) {
            const fileData = await file.createReadStream().pipe(csv()).toArray();
            fileData.forEach(row => {
                const assetName = row['DNS'];
                const ipAddress = row['IP'];
                if (!assetVulnerabilityCounts[assetName]) {
                    assetVulnerabilityCounts[assetName] = {
                        NumActive: 0,
                        NumNew: 0,
                        NumFixed: 0,
                        IpAddresses: new Set(),
                    };
                }

                if (ipAddress) {
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
        await deleteExistingTable(bigquery, datasetId, tableId);
        await createReportingTable(bigquery, datasetId, tableId);
        await new Promise(resolve => setTimeout(resolve, 5000)); // Adjust delay as needed
        await insertDataIntoReportingTable(bigquery, datasetId, tableId, assetVulnerabilityCounts);
        console.log('Data successfully inserted into BigQuery.');
    } catch (error) {
        console.error('Error writing data to BigQuery:', error);
    }
};

async function deleteExistingTable(bigquery, datasetId, tableId) {
    try {
        const dataset = bigquery.dataset(datasetId);
        const table = dataset.table(tableId);

        const [exists] = await table.exists();
        if (exists) {
            await table.delete();
            console.log('Existing table deleted successfully.');
        } else {
            console.log('Table does not exist. Skipping deletion.');
        }
    } catch (error) {
        console.error(`Error deleting existing table: ${error}`);
    }
}

async function createReportingTable(bigquery, datasetId, tableId) {
    try {
        const dataset = bigquery.dataset(datasetId);
        const [table] = await dataset.createTable(tableId, {
            schema: {
                fields: [
                    { name: 'IPAddress', type: 'STRING' },
                    { name: 'AssetName', type: 'STRING' },
                    { name: 'NumVulnerabilitiesPresent', type: 'INTEGER' },
                    { name: 'NumPreviouslyDiscovered', type: 'INTEGER' },
                    { name: 'NumNewlyDiscovered', type: 'INTEGER' },
                    { name: 'NumRemediated', type: 'INTEGER' },
                ],
            },
            exists: 'skip'
        });

        console.log(`Table ${tableId} created successfully.`);
    } catch (error) {
        if (!error.message.includes('Already Exists:')) {
            throw new Error(`Error creating reporting table: ${error}`);
        }
    }
}

async function insertDataIntoReportingTable(bigquery, datasetId, tableId, assetVulnerabilityCounts) {
    try {
        const dataset = bigquery.dataset(datasetId);
        const table = dataset.table(tableId);
        const rowsToInsert = [];
        for (const assetName in assetVulnerabilityCounts) {
            const { NumActive, NumNew, NumFixed, IpAddresses } = assetVulnerabilityCounts[assetName];
            Array.from(IpAddresses).forEach(ipAddress => {
                rowsToInsert.push({
                    IPAddress: ipAddress,
                    AssetName: assetName,
                    NumVulnerabilitiesPresent: NumActive + NumFixed,
                    NumPreviouslyDiscovered: NumActive - NumNew,
                    NumNewlyDiscovered: NumNew,
                    NumRemediated: NumFixed,
                });
            });
        }
        await table.insert(rowsToInsert);

        console.log('New data inserted successfully.');
    } catch (error) {
        throw new Error(`Error inserting new data into reporting table: ${error}`);
    }
}
