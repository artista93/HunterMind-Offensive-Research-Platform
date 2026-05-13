# interfaces/api/__init__.py

"""
API Module - واجهة REST API و WebSocket و gRPC
"""

from .api_models import (
    Severity, Confidence, ScanType, AttackType,
    ScanRequest, ScanResponse, ScanResult,
    Finding, AttackRequest, AttackResponse, AttackResult,
    ExploitRequest, ExploitResult,
    HealthResponse, ErrorResponse, ListResponse,
    WebSocketMessage, WebSocketStats,
    GRPCHealthRequest, GRPCHealthResponse,
    GRPCScanRequest, GRPCScanResponse, GRPCGetResultsRequest,
)

from .fastapi_server import app, run_scan, run_attack, run_exploit

from .websocket_api import (
    ConnectionManager, manager,
    websocket_endpoint, websocket_channel_endpoint,
    handle_message, handle_channel_message,
    get_websocket_stats, broadcast_message,
)

from .grpc_server import GRPCServer, HunterMindServicer, get_grpc_server

__all__ = [
    # api_models
    'Severity', 'Confidence', 'ScanType', 'AttackType',
    'ScanRequest', 'ScanResponse', 'ScanResult',
    'Finding', 'AttackRequest', 'AttackResponse', 'AttackResult',
    'ExploitRequest', 'ExploitResult',
    'HealthResponse', 'ErrorResponse', 'ListResponse',
    'WebSocketMessage', 'WebSocketStats',
    'GRPCHealthRequest', 'GRPCHealthResponse',
    'GRPCScanRequest', 'GRPCScanResponse', 'GRPCGetResultsRequest',
    # fastapi_server
    'app', 'run_scan', 'run_attack', 'run_exploit',
    # websocket_api
    'ConnectionManager', 'manager',
    'websocket_endpoint', 'websocket_channel_endpoint',
    'handle_message', 'handle_channel_message',
    'get_websocket_stats', 'broadcast_message',
    # grpc_server
    'GRPCServer', 'HunterMindServicer', 'get_grpc_server',
]
