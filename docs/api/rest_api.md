
🔌 REST API Documentation

Base URL

```
http://localhost:8000
```

Endpoints

Health Check

```
GET /health
```

Response:

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T10:00:00"
}
```

Start Scan

```
POST /scan
```

Request:

```json
{
  "target_url": "https://example.com",
  "scan_type": "full",
  "max_depth": 3,
  "max_pages": 100
}
```

Response:

```json
{
  "scan_id": "abc123",
  "status": "started",
  "message": "Scan started for https://example.com"
}
```

Get Scan Results

```
GET /results/{scan_id}
```

Response:

```json
{
  "scan_id": "abc123",
  "target_url": "https://example.com",
  "status": "completed",
  "findings": [
    {
      "type": "XSS",
      "severity": "high",
      "url": "https://example.com/search",
      "parameter": "q"
    }
  ]
}
```

Start Attack

```
POST /attack
```

Request:

```json
{
  "target_url": "https://example.com",
  "vulnerability_type": "xss",
  "parameter": "q"
}
```

WebSocket

```
ws://localhost:8001/ws/{client_id}
```

Error Responses

```json
{
  "error": "Scan not found",
  "timestamp": "2024-01-01T10:00:00"
}
```

