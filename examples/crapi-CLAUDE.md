# Engagement Brief — crAPI

## Target
- URL: http://localhost:8888
- Type: REST API + Web Application
- Description: Vehicle management platform — users register vehicles, book workshop services, shop for parts, and interact via community forum.

## Scope
- http://localhost:8888/*

## Tech Stack
- REST API (JSON)
- JWT-based authentication
- Mobile-style API design (versioned endpoints: /v2/, /v3/)

## Authentication
- Users register and log in via email/password
- Auth token returned on login — passed as Bearer token in Authorization header

## What I Know Going In
- Two test accounts will be created before the scan
- The app manages user-owned resources (vehicles, orders, reports)
- Community and workshop features are available post-login

## Testing Goals
- Map all API endpoints from proxy traffic
- Identify and confirm vulnerabilities through active testing
- Focus on business logic, authorization, and data access issues
