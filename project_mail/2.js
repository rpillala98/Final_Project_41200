// const { BigQuery } = require('@google-cloud/bigquery');
// const { Storage } = require('@google-cloud/storage');
// const csv = require('csv-parser');

// exports.WriteToBigQuery = async (message, context) => {
//     try {
//         // Initialize BigQuery client
//         const bigquery = new BigQuery();

//         // Define BigQuery dataset and table
//         const datasetId = 'vulnerability_report';
//         const tableId = 'Reporting';

//         // Initialize Storage client
//         const storage = new Storage();

//         // Define bucket name
//         const bucketName = 'vulnerability_report'; // Remove gs:// prefix

//         // Read data from CSV files in the bucket
//         const [files] = await storage.bucket(bucketName).getFiles();

//         // Object to store vulnerability counts for each asset
//         const assetVulnerabilityCounts = {};

//         for (const file of files) {
//             const fileData = await file.createReadStream().pipe(csv()).toArray();
//             fileData.forEach(row => {
//                 const assetName = row['DNS'];
//                 if (!assetVulnerabilityCounts[assetName]) {
//                     assetVulnerabilityCounts[assetName] = {
//                         NumActive: 0,
//                         NumNew: 0,
//                         NumFixed: 0,
//                     };
//                 }

//                 if (row['Vuln Status'] === 'Active' || row['Vuln Status'] === 'New') {
//                     assetVulnerabilityCounts[assetName].NumActive++;
//                     if (row['Vuln Status'] === 'New') {
//                         assetVulnerabilityCounts[assetName].NumNew++;
//                     }
//                 } else if (row['Vuln Status'] === 'Fixed') {
//                     assetVulnerabilityCounts[assetName].NumFixed++;
//                 }
//             });
//         }

//         // Update or insert data into BigQuery for each asset
//         const dataset = bigquery.dataset(datasetId);
//         const table = dataset.table(tableId);

//         for (const assetName in assetVulnerabilityCounts) {
//             const { NumActive, NumNew, NumFixed } = assetVulnerabilityCounts[assetName];
//             const rowsToInsert = [
//                 {
//                     AssetName: assetName,
//                     NumVulnerabilitiesPresent: NumActive + NumFixed,
//                     NumPreviouslyDiscovered: NumActive - NumNew,
//                     NumNewlyDiscovered: NumNew,
//                     NumRemediated: NumFixed,
//                 },
//             ];

//             // Check if the asset already exists in the table
//             const query = `SELECT * FROM ${tableId} WHERE AssetName='${assetName}'`;
//             const [rows] = await bigquery.query(query);

//             if (rows && rows.length > 0) {
//                 // If asset exists, update the existing row
//                 await table.update(rowsToInsert);
//             } else {
//                 // If asset doesn't exist, insert a new row
//                 await table.insert(rowsToInsert);
//             }
//         }

//         console.log('Data successfully inserted or updated in BigQuery.');

//     } catch (error) {
//         console.error('Error writing data to BigQuery:', error);
//     }
// };


// const { BigQuery } = require('@google-cloud/bigquery');
// const { Storage } = require('@google-cloud/storage');
// const csv = require('csv-parser');

// exports.WriteToBigQuery = async (message, context) => {
//     try {
//         // Initialize BigQuery client
//         const bigquery = new BigQuery();

//         // Define BigQuery dataset and table
//         const datasetId = 'vulnerability_report';
//         const tableId = 'Reporting';

//         // Initialize Storage client
//         const storage = new Storage();

//         // Define bucket name
//         const bucketName = 'vulnerability_report'; // Remove gs:// prefix

//         // Read data from CSV files in the bucket
//         const [files] = await storage.bucket(bucketName).getFiles();

//         // Object to store vulnerability counts for each asset
//         const assetVulnerabilityCounts = {};

//         for (const file of files) {
//             const fileData = await file.createReadStream().pipe(csv()).toArray();
//             fileData.forEach(row => {
//                 const assetName = row['DNS'];
//                 if (!assetVulnerabilityCounts[assetName]) {
//                     assetVulnerabilityCounts[assetName] = {
//                         NumActive: 0,
//                         NumNew: 0,
//                         NumFixed: 0,
//                     };
//                 }

//                 if (row['Vuln Status'] === 'Active' || row['Vuln Status'] === 'New') {
//                     assetVulnerabilityCounts[assetName].NumActive++;
//                     if (row['Vuln Status'] === 'New') {
//                         assetVulnerabilityCounts[assetName].NumNew++;
//                     }
//                 } else if (row['Vuln Status'] === 'Fixed') {
//                     assetVulnerabilityCounts[assetName].NumFixed++;
//                 }
//             });
//         }

//         // Update or insert data into BigQuery for each asset
//         const dataset = bigquery.dataset(datasetId);
//         const table = dataset.table(tableId);

//         for (const assetName in assetVulnerabilityCounts) {
//             const { NumActive, NumNew, NumFixed } = assetVulnerabilityCounts[assetName];
//             const rowsToInsert = [
//                 {
//                     AssetName: assetName,
//                     NumVulnerabilitiesPresent: NumActive + NumFixed,
//                     NumPreviouslyDiscovered: NumActive - NumNew,
//                     NumNewlyDiscovered: NumNew,
//                     NumRemediated: NumFixed,
//                 },
//             ];

//             // Check if the asset already exists in the table
//             const query = `SELECT * FROM ${tableId} WHERE AssetName='${assetName}'`;
//             const [rows] = await bigquery.query(query);

//             if (rows && rows.length > 0) {
//                 // If asset exists, update the existing row
//                 await table.update(rowsToInsert);
//             } else {
//                 // If asset doesn't exist, insert a new row
//                 await table.insert(rowsToInsert);
//             }
//         }

//         console.log('Data successfully inserted or updated in BigQuery.');

//     } catch (error) {
//         console.error('Error writing data to BigQuery:', error);
//     }
// };


// const { BigQuery } = require('@google-cloud/bigquery');
// const { Storage } = require('@google-cloud/storage');
// const csv = require('csv-parser');

// exports.WriteToBigQuery = async (message, context) => {
//     try {
//         // Initialize BigQuery client
//         const bigquery = new BigQuery();

//         // Define BigQuery dataset and table
//         const datasetId = 'vulnerability_report';
//         const tableId = 'Reporting';

//         // Initialize Storage client
//         const storage = new Storage();

//         // Define bucket name
//         const bucketName = 'vulnerability_report'; // Remove gs:// prefix

//         // Read data from CSV files in the bucket
//         const [files] = await storage.bucket(bucketName).getFiles();

//         // Object to store vulnerability counts for each asset
//         const assetVulnerabilityCounts = {};

//         for (const file of files) {
//             const fileData = await file.createReadStream().pipe(csv()).toArray();
//             fileData.forEach(row => {
//                 const assetName = row['DNS'];
//                 if (!assetVulnerabilityCounts[assetName]) {
//                     assetVulnerabilityCounts[assetName] = {
//                         NumActive: 0,
//                         NumNew: 0,
//                         NumFixed: 0,
//                     };
//                 }

//                 if (row['Vuln Status'] === 'Active' || row['Vuln Status'] === 'New') {
//                     assetVulnerabilityCounts[assetName].NumActive++;
//                     if (row['Vuln Status'] === 'New') {
//                         assetVulnerabilityCounts[assetName].NumNew++;
//                     }
//                 } else if (row['Vuln Status'] === 'Fixed') {
//                     assetVulnerabilityCounts[assetName].NumFixed++;
//                 }
//             });
//         }

//         // Update or insert data into BigQuery for each asset
//         const dataset = bigquery.dataset(datasetId);

//         for (const assetName in assetVulnerabilityCounts) {
//             const { NumActive, NumNew, NumFixed } = assetVulnerabilityCounts[assetName];
//             const rowsToInsert = [
//                 {
//                     AssetName: assetName,
//                     NumVulnerabilitiesPresent: NumActive + NumFixed,
//                     NumPreviouslyDiscovered: NumActive - NumNew,
//                     NumNewlyDiscovered: NumNew,
//                     NumRemediated: NumFixed,
//                 },
//             ];

//             // Check if the asset already exists in the table
//             const table = dataset.table(tableId); // Qualify table with dataset
//             const query = `SELECT * FROM ${datasetId}.${tableId} WHERE AssetName='${assetName}'`;
//             const [rows] = await bigquery.query(query);

//             if (rows && rows.length > 0) {
//                 // If asset exists, update the existing row
//                 await table.update(rowsToInsert);
//             } else {
//                 // If asset doesn't exist, insert a new row
//                 await table.insert(rowsToInsert);
//             }
//         }

//         console.log('Data successfully inserted or updated in BigQuery.');

//     } catch (error) {
//         console.error('Error writing data to BigQuery:', error);
//     }
// };

// const { BigQuery } = require('@google-cloud/bigquery');
// const { Storage } = require('@google-cloud/storage');
// const csv = require('csv-parser');

// exports.WriteToBigQuery = async (message, context) => {
//     try {
//         // Initialize BigQuery client
//         const bigquery = new BigQuery();

//         // Define BigQuery dataset and table
//         const datasetId = 'vulnerability_report';
//         const tableId = 'Reporting';

//         // Initialize Storage client
//         const storage = new Storage();

//         // Define bucket name
//         const bucketName = 'vulnerability_report'; // Remove gs:// prefix

//         // Read data from CSV files in the bucket
//         const [files] = await storage.bucket(bucketName).getFiles();

//         // Object to store vulnerability counts for each asset
//         const assetVulnerabilityCounts = {};

//         for (const file of files) {
//             const fileData = await file.createReadStream().pipe(csv()).toArray();
//             fileData.forEach(row => {
//                 const assetName = row['DNS'];
//                 if (!assetVulnerabilityCounts[assetName]) {
//                     assetVulnerabilityCounts[assetName] = {
//                         IpAddress: 'Null',
//                         NumActive: 0,
//                         NumNew: 0,
//                         NumFixed: 0,
//                     };
//                 }

//                 if (row['Vuln Status'] === 'Active' || row['Vuln Status'] === 'New') {
//                     assetVulnerabilityCounts[assetName].NumActive++;
//                     if (row['Vuln Status'] === 'New') {
//                         assetVulnerabilityCounts[assetName].NumNew++;
//                     }
//                 } else if (row['Vuln Status'] === 'Fixed') {
//                     assetVulnerabilityCounts[assetName].NumFixed++;
//                 }
//             });
//         }

//         // Update or insert data into BigQuery for each asset
//         const dataset = bigquery.dataset(datasetId);

//         // Update or insert data into BigQuery for each asset
// for (const assetName in assetVulnerabilityCounts) {
//     const { IpAddress, NumActive, NumNew, NumFixed } = assetVulnerabilityCounts[assetName];
//     const rowsToUpsert = [
//         {
//             IpAddress: IpAddress,
//             AssetName: assetName,
//             NumVulnerabilitiesPresent: NumActive + NumFixed,
//             NumPreviouslyDiscovered: NumActive - NumNew,
//             NumNewlyDiscovered: NumNew,
//             NumRemediated: NumFixed,
//         },
//     ];

//     // Check if the asset already exists in the table
//     const table = dataset.table(tableId); // Qualify table with dataset
//     const query = `SELECT * FROM ${datasetId}.${tableId} WHERE AssetName='${assetName}'`;
//     const [rows] = await bigquery.query(query);

//     if (rows && rows.length > 0) {
//         // If asset exists, update the existing row
//         const rowToUpdate = rows[0];
//         const metadata = {
//             // Specify the primary key column(s) for upsert
//             key: ['AssetName'],
//         };
//         const [updateResponse] = await table.upsert(rowsToUpsert, metadata);
//         console.log(`Updated row: ${updateResponse}`);
//     } else {
//         // If asset doesn't exist, insert a new row
//         const [insertResponse] = await table.insert(rowsToUpsert);
//         console.log(`Inserted row: ${insertResponse}`);
//     }
// }

// console.log('Data successfully inserted or updated in BigQuery.');

//     } catch (error) {
//         console.error('Error writing data to BigQuery:', error);
//     }
// };

// const { BigQuery } = require('@google-cloud/bigquery');
// const { Storage } = require('@google-cloud/storage');
// const csv = require('csv-parser');

// exports.WriteToBigQuery = async (message, context) => {
//     try {
//         // Initialize BigQuery client
//         const bigquery = new BigQuery();

//         // Define BigQuery dataset and table
//         const datasetId = 'vulnerability_report';
//         const tableId = 'Reporting';

//         // Initialize Storage client
//         const storage = new Storage();

//         // Define bucket name
//         const bucketName = 'vulnerability_report'; // Remove gs:// prefix

//         // Read data from CSV files in the bucket
//         const [files] = await storage.bucket(bucketName).getFiles();

//         // Object to store vulnerability counts for each asset
//         const assetVulnerabilityCounts = {};

//         for (const file of files) {
//             const fileData = await new Promise((resolve, reject) => {
//                 let data = [];
//                 file.createReadStream()
//                     .pipe(csv())
//                     .on('data', (row) => {
//                         data.push(row);
//                     })
//                     .on('end', () => {
//                         resolve(data);
//                     })
//                     .on('error', (error) => {
//                         reject(error);
//                     });
//             });

//             fileData.forEach(row => {
//                 const assetName = row['DNS'];
//                 const ipAddress = row['IpAddress']; // Added line to retrieve IP address
//                 if (!assetVulnerabilityCounts[assetName]) {
//                     assetVulnerabilityCounts[assetName] = {
//                         IpAddress: ipAddress || 'Null', // Set IP address or default to 'Null' if not provided
//                         NumActive: 0,
//                         NumNew: 0,
//                         NumFixed: 0,
//                     };
//                 }

//                 if (row['Vuln Status'] === 'Active' || row['Vuln Status'] === 'New') {
//                     assetVulnerabilityCounts[assetName].NumActive++;
//                     if (row['Vuln Status'] === 'New') {
//                         assetVulnerabilityCounts[assetName].NumNew++;
//                     }
//                 } else if (row['Vuln Status'] === 'Fixed') {
//                     assetVulnerabilityCounts[assetName].NumFixed++;
//                 }
//             });
//         }

//         // Update or insert data into BigQuery for each asset
//         const dataset = bigquery.dataset(datasetId);

//         for (const assetName in assetVulnerabilityCounts) {
//             const { IpAddress, NumActive, NumNew, NumFixed } = assetVulnerabilityCounts[assetName];
//             const rowsToUpsert = [
//                 {
//                     IpAddress: IpAddress,
//                     AssetName: assetName,
//                     NumVulnerabilitiesPresent: NumActive + NumFixed,
//                     NumPreviouslyDiscovered: NumActive - NumNew,
//                     NumNewlyDiscovered: NumNew,
//                     NumRemediated: NumFixed,
//                 },
//             ];

//             const table = dataset.table(tableId);
//             const query = `SELECT * FROM ${datasetId}.${tableId} WHERE AssetName='${assetName}'`;
//             const [rows] = await bigquery.query(query);

//             if (rows && rows.length > 0) {
//                 const metadata = {
//                     key: ['AssetName'],
//                 };
//                 const [updateResponse] = await table.upsert(rowsToUpsert, metadata);
//                 console.log(`Updated row: ${JSON.stringify(updateResponse)}`); // Changed logging to stringify response
//             } else {
//                 const [insertResponse] = await table.insert(rowsToUpsert);
//                 console.log(`Inserted row: ${JSON.stringify(insertResponse)}`); // Changed logging to stringify response
//             }
//         }

//         console.log('Data successfully inserted or updated in BigQuery.');

//     } catch (error) {
//         console.error('Error writing data to BigQuery:', error);
//     }
// };

// const { BigQuery } = require('@google-cloud/bigquery');
// const { Storage } = require('@google-cloud/storage');
// const csv = require('csv-parser');

// exports.WriteToBigQuery = async (message, context) => {
//     try {
//         // Initialize BigQuery client
//         const bigquery = new BigQuery();

//         // Define BigQuery dataset and table
//         const datasetId = 'vulnerability_report';
//         const tableId = 'Reporting';

//         // Initialize Storage client
//         const storage = new Storage();

//         // Define bucket name
//         const bucketName = 'vulnerability_report'; // Remove gs:// prefix

//         // Read data from CSV files in the bucket
//         const [files] = await storage.bucket(bucketName).getFiles();

//         // Object to store vulnerability counts for each asset
//         const assetVulnerabilityCounts = {};

//         for (const file of files) {
//             const fileData = await file.createReadStream().pipe(csv()).toArray();
//             fileData.forEach(row => {
//                 const assetName = row['DNS'];
//                 if (!assetVulnerabilityCounts[assetName]) {
//                     assetVulnerabilityCounts[assetName] = {
//                         NumActive: 0,
//                         NumNew: 0,
//                         NumFixed: 0,
//                         IpAddresses: new Set(), // Store unique IP addresses for each asset
//                     };
//                 }

//                 const ipAddress = row['IP']; // Assuming the column name is 'IP'
//                 assetVulnerabilityCounts[assetName].IpAddresses.add(ipAddress);

//                 if (row['Vuln Status'] === 'Active' || row['Vuln Status'] === 'New') {
//                     assetVulnerabilityCounts[assetName].NumActive++;
//                     if (row['Vuln Status'] === 'New') {
//                         assetVulnerabilityCounts[assetName].NumNew++;
//                     }
//                 } else if (row['Vuln Status'] === 'Fixed') {
//                     assetVulnerabilityCounts[assetName].NumFixed++;
//                 }
//             });
//         }

//         // Update or insert data into BigQuery for each asset
//         const dataset = bigquery.dataset(datasetId);

//         for (const assetName in assetVulnerabilityCounts) {
//             const { NumActive, NumNew, NumFixed, IpAddresses } = assetVulnerabilityCounts[assetName];
//             const rowsToInsert = Array.from(IpAddresses).map(ipAddress => ({
//                 IP: ipAddress,
//                 AssetName: assetName,
//                 NumVulnerabilitiesPresent: NumActive + NumFixed,
//                 NumPreviouslyDiscovered: NumActive - NumNew,
//                 NumNewlyDiscovered: NumNew,
//                 NumRemediated: NumFixed,
//             }));

//             // Check if the asset already exists in the table
//             const table = dataset.table(tableId); // Qualify table with dataset
//             const query = `SELECT * FROM ${datasetId}.${tableId} WHERE AssetName='${assetName}'`;
//             const [rows] = await bigquery.query(query);

//             if (rows && rows.length > 0) {
//                 // If asset exists, update the existing rows
//                 await table.insert(rowsToInsert);
//             } else {
//                 // If asset doesn't exist, insert new rows
//                 await table.insert(rowsToInsert);
//             }
//         }

//         console.log('Data successfully inserted or updated in BigQuery.');

//     } catch (error) {
//         console.error('Error writing data to BigQuery:', error);
//     }
// };






