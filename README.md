# Threat-Matrix

**Live Deployment:** [Threat-Matrix](https://threat-matrix.pages.dev/)

Threat-Matrix is a serverless, edge-native threat intelligence dashboard. It is designed to aggregate, stream, and monitor global cybersecurity threat logs, vulnerability feeds, and security news in a single, unified interface. 

The platform allows users to create secure profiles, filter incoming intelligence based on specific tracking parameters, and interact with the data by logging likes and comments on critical threat bulletins.

## Project Philosophy & Limitations

This project was built to be completely free, privacy-respecting, and independent. There is zero ad tracking, and it operates without storing sensitive personal data (no emails required). Because the architecture relies on a fully free infrastructure tier to keep the service accessible, it uses a Cloudflare `.pages.dev` domain. 

Additionally, while the app aggregates data from major security outlets, some advanced intelligence feeds are restricted by heavy API paywalls. The current sources are selected to provide the best possible free coverage. Future donations to the project will go directly toward upgrading the domain and unlocking premium API feeds to bypass these limitations.

## Core Capabilities

* **Threat Intelligence Aggregation:** Pulls and normalizes live data from multiple cybersecurity sources, including the National Vulnerability Database (NVD CVEs), CISA Known Exploited Vulnerabilities (KEVs), CIRCL, and global security news feeds.
* **Custom Tracking Parameters:** Users can define specific tags and parameters to filter the intelligence stream, focusing only on the threats relevant to their specific stack or interests.
* **Secure Authentication:** Features a custom zero-trust authentication system using the native Web Crypto API for SHA-256 password hashing and salt generation, protected by Cloudflare Turnstile. Account creation requires only a username and a cryptographic passphrase (128 characters) to maintain total user privacy.
* **Interactive Threat Logging:** Users can engage with individual threat logs by "liking" them or leaving persistent comments for team review or personal notes.

## System Architecture

Threat-Matrix is built as a monorepo utilizing a fully serverless, global edge-network stack powered by Cloudflare:

* **Frontend (Web Interface):** Built with React, Vite, and TypeScript. It utilizes an optimistic UI for seamless data interaction and is designed to be deployed on Cloudflare Pages.
* **Backend (API Gateway):** Powered by Cloudflare Workers written in TypeScript. It handles cross-origin requests, input sanitization, external API fetching, and user authentication natively at the edge.
* **Database (Datastore):** Utilizes Cloudflare D1, a serverless SQLite database built on Cloudflare's edge network, to securely store user profiles, tracking parameters, likes, and comments with sub-millisecond query latency.

## Donation

Contact me on: [Telegram](https://t.me/TetstackPM)
