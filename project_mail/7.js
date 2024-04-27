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

        for (const file of files) {
            const fileData = await file.createReadStream().pipe(csv()).toArray();

            for (const row of fileData) {
                const assetName = row['DNS'];
                const ipAddress = row['IP'];
                const version = new Date(); // Use current timestamp as version

                // Insert latest scan details for the asset
                await bigquery
                    .dataset(datasetId)
                    .table(tableId)
                    .insert({
                        IPAddress: ipAddress,
                        AssetName: assetName,
                        NumVulnerabilitiesPresent: row['Vuln Status'] === 'Fixed' ? 0 : 1,
                        NumPreviouslyDiscovered: row['Vuln Status'] === 'New' ? 1 : 0,
                        NumNewlyDiscovered: row['Vuln Status'] === 'New' ? 1 : 0,
                        NumRemediated: row['Vuln Status'] === 'Fixed' ? 1 : 0,
                        Version: version
                    });

                // Insert previous scan details for the same asset
                await bigquery
                    .dataset(datasetId)
                    .table(tableId)
                    .insert({
                        IPAddress: ipAddress,
                        AssetName: assetName,
                        NumVulnerabilitiesPresent: 0, // Placeholder for previous scan details
                        NumPreviouslyDiscovered: 0,  // Placeholder for previous scan details
                        NumNewlyDiscovered: 0,       // Placeholder for previous scan details
                        NumRemediated: 0,            // Placeholder for previous scan details
                        Version: version
                    });
            }
        }

        console.log('Data successfully inserted into BigQuery.');

    } catch (error) {
        console.error('Error writing data to BigQuery:', error);
    }
};

