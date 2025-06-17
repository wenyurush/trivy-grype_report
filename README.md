# 🛡️ Vulnerability Report Generator for Trivy & Grype

![alt text](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare)

This project provides a simple yet powerful web application to convert security scan reports from **Trivy** and **Grype** into beautiful, interactive, and self-contained HTML reports.

It consists of two main parts:
1.  **A static frontend (`index.html`)** for uploading JSON report files.
2.  **A serverless backend (`index.ts`)** built with Hono for Cloudflare Workers that processes the JSON and generates the final HTML report.

[**➡️ Online Demo**](https://report.xecho.org)

[](https://report.xecho.org)
*The user-friendly upload interface.*

[](https://report.xecho.org)
*An example of the interactive HTML report.*

## ✨ Key Features

-   **Dual Scanner Support**: Natively parses JSON output from both [Trivy](https://github.com/aquasecurity/trivy) and [Grype](https://github.com/anchore/grype).
-   **Interactive Dashboard**: The generated report includes an interactive dashboard with summary cards and detailed statistics.
-   **Dynamic Filtering and Searching**: Easily filter vulnerabilities by severity, package name, location, or type. A live search bar helps you find specific CVEs or packages instantly.
-   **Clickable Statistics**: Drill down into the data by clicking on stats tables to automatically apply filters to the main vulnerability list.
-   **Single-File & Portable**: The generated report is a single, self-contained HTML file with no external dependencies, making it easy to share and archive.
-   **Modern UI**: Clean, responsive, and user-friendly interface for both the uploader and the report.
-   **Serverless & Scalable**: Built on Cloudflare Workers, the backend is fast, scalable, and cost-effective.

## 🚀 How to Use

### 1. Generate a Scan Report

First, scan your container image or filesystem using either Trivy or Grype and ensure the output is in JSON format.

**For Grype:**
```bash
# Replace 'image:tag' with your target image
grype image:tag --scope all-layers -o json > image_tag.grype.json
```

**For Trivy:**
```bash
# Replace 'image:tag' with your target image
trivy image image:tag --format json -o image_tag.trivy.json
```

### 2. Upload and Generate

1.  Navigate to the [**Vulnerability Report Generator**](https://report.xecho.org).
2.  Drag and drop your `grype.json` or `trivy.json` file onto the upload area, or click to select the file.
3.  Click the "🚀 Generate Report" button.
4.  A new browser tab will open with your interactive HTML report.

## 🛠️ How It Works

The architecture is simple and decoupled:

1.  **Frontend (`index.html`)**: A static web page that provides the UI for file uploads. It sends the selected JSON file to the backend API.
2.  **Backend (`index.ts` on Cloudflare Workers)**:
    -   Receives the file via a `POST` request to the `/upload` endpoint.
    -   Detects whether the file is a Trivy or Grype report.
    -   Parses the JSON into a standardized `Vulnerability` data structure.
    -   Calculates detailed statistics (e.g., counts by severity, package, location).
    -   Injects the data and statistics into a templated HTML string.
    -   The template includes JavaScript for all the interactive filtering, sorting, and UI logic.
    -   Returns the complete, self-contained HTML report as the response.

## 🔧 Deployment (Self-Hosting)

You can easily deploy your own instance of this tool.

### Prerequisites

-   [Node.js](https://nodejs.org/) and npm.
-   A [Cloudflare account](https://dash.cloudflare.com/sign-up).
-   [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/install-and-update/) installed globally: `npm install -g wrangler`.

### Backend (Cloudflare Worker)

1.  Clone this repository.
2.  Navigate to the backend directory:
    ```bash
    cd api/
    ```
3.  Install dependencies:
    ```bash
    npm install
    ```
4.  Log in to your Cloudflare account:
    ```bash
    npx wrangler login
    ```
5.  **Crucially**, you need to update the CORS policy in `src/index.ts` to allow requests from the domain where you will host your frontend. Change `https://report.xecho.org` to your frontend's URL (or `*` for local testing, though not recommended for production).
    ```typescript
    // in api/src/index.ts
    app.use('/upload', cors({
      origin: 'https://your-frontend-domain.com', // <-- CHANGE THIS
      allowMethods: ['POST', 'OPTIONS'],
    }));
    ```
6.  Deploy the worker:
    ```bash
    npx wrangler deploy
    ```
    Wrangler will output the URL of your deployed worker (e.g., `https://api-report.<your-account>.workers.dev`). **Copy this URL.**

### Frontend (Static Site)

The frontend is a single `index.html` file. You can host it on any static hosting provider like GitHub Pages, Vercel, or Cloudflare Pages.

1.  Open the `index.html` file.
2.  Find the `<form>` tag and update the `action` attribute to point to your newly deployed Cloudflare Worker URL.

    ```html
    <!-- in index.html -->
    <form id="upload-form" action="https://your-worker-url/upload" method="post" enctype="multipart/form-data" target="_blank">
      <!-- ... -->
    </form>
    ```
3.  Deploy the modified `index.html` file to your static hosting provider.

Now you have a fully working, self-hosted version of the report generator!

## 📂 Project Structure

```
.
├── index.html         # The static frontend uploader page.
├── index.ts           # The Cloudflare Worker backend (Hono app).
└── README.md          # This file.
```

(Note: For a production setup, the `index.ts` file would typically reside in a directory structure like `api/src/index.ts` with a corresponding `package.json` and `wrangler.toml`.)

## 🤝 Contributing

Contributions are welcome! If you have ideas for improvements, new features, or find a bug, please feel free to open an issue or submit a pull request.

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

---

> Forged in human-AI light.
