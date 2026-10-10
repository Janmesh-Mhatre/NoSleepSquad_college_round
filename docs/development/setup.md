# Incognito — Development & Testing Guide

## Prerequisites
- Node.js v20+ (Node v24 recommended)
- npm v10+

## Getting Started

1. **Install Dependencies**:
   ```bash
   npm install
   ```

2. **Start Backend API Server**:
   ```bash
   npm run server
   ```
   *Runs on `http://localhost:4000` with automated SQLite initialization and database seeding.*

3. **Start Frontend Dev Server**:
   ```bash
   npm run dev
   ```
   *Runs on `http://localhost:5173` with reverse proxy forwarding `/api` and `/health` requests to `http://localhost:4000`.*

4. **Production Build & Type Check**:
   ```bash
   npm run build
   ```

5. **Run Test Suites**:
   - Run backend tests:
     ```bash
     npm run test:backend
     ```
   - Run frontend tests:
     ```bash
     npm run test:frontend
     ```
   - Run both suites:
     ```bash
     npm test
     ```
