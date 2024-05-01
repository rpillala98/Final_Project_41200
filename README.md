# Vulnerability Reporting System 

## Overview

The Vulnerability Reporting System is a comprehensive solution designed to streamline vulnerability management and communication processes. Leveraging Google Cloud Platform (GCP) resources and SendGrid, the system automates vulnerability scanning, generates personalized reports, and provides real-time data visualization for stakeholders.

### Getting Started
#### Prerequisites
Before getting started, ensure you have the following prerequisites installed and set up:

**Google Cloud Platform (GCP) Account**: You'll need a GCP account with necessary permissions to deploy cloud functions, utilize GCP resources, and access services like Firestore, BigQuery, and Looker Studio.
**Qualys Account**: Obtain access to Qualys platform for vulnerability scanning and report generation.
**SendGrid Account**: Sign up for a SendGrid account to enable email notifications and communication with subscribers.

#### Project Setup
**1. Clone the Repository**: Clone the project repository from Git to your local machine.

```git clone https://github.com/rpillala98/Final_Project_41200```

**2. Navigate to Project Directories**:
- **`project_mail`**: Navigate to the **`project_mail`** directory to deploy the cloud functions.

```cd project_mail```

- **`web`**: Navigate to the **`web directory`** under **`project_mail`** directory to run the web application.

```cd web```

**3. Install Dependencies**:
- In the **`project_mail`** directory, ensure you have Node.js installed, and install the necessary dependencies using npm.

```npm install @sendgrid/mail @google-cloud/storage @google-cloud/firestore @google-cloud/bigquery csv-parser fs path```

- Similarly, in the **`web directory`**, install required dependencies for the web application.
```npm install express path @google-cloud/pubsub body-parser```

**4. Set Up Environment Variables**:
Set up environment variables for necessary credentials and API keys required for GCP, and SendGrid. Refer to respective documentation for obtaining and configuring these credentials.

**5. Deploy Cloud Functions**:
Deploy the cloud functions from the **`project_mail`** directory using the provided command.
```gcloud functions deploy VRS --runtime nodejs18 --trigger-topic vulnerability_report --entry-point Main --no-gen2```

**6. Run Web Application**:
Run the web application from the **`web`** directory using Node.js.

**7. Access Vulnerability Reports**:
- From the GCP console, click on "Web Preview" and preview on port 8080.
- Fill out the subscription form with your email address and asset name to subscribe and receive vulnerability reports.

**8. Monitor Vulnerability Trends**:
- Access Looker Studio by navigating to the Looker Studio platform in your GCP console. 
- Explore the visualized vulnerability data and trends for informed decision-making.