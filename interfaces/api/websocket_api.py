
import asyncio
import json
from typing import Dict, Set, Any
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
import uvicorn

import logging

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    مدير اتصالات WebSocket
    يدير الاتصالات النشطة ويوزع الرسائل
    """
    
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, client_id: str, channel: str = "default"):
        """
        قبول اتصال جديد
        
        Args:
            websocket: كائن WebSocket
            client_id: معرف العميل
            channel: القناة
        """
        await websocket.accept()
        
        async with self._lock:
            if channel not in self.active_connections:
                self.active_connections[channel] = set()
            self.active_connections[channel].add(websocket)
        
        logger.info(f"Client {client_id} connected to channel {channel}")
    
    async def disconnect(self, websocket: WebSocket, channel: str = "default"):
        """
        قطع اتصال عميل
        
        Args:
            websocket: كائن WebSocket
            channel: القناة
        """
        async with self._lock:
            if channel in self.active_connections:
                self.active_connections[channel].discard(websocket)
        
        logger.info(f"Client disconnected from channel {channel}")
    
    async def send_personal(self, message: dict, websocket: WebSocket):
        """
        إرسال رسالة شخصية
        
        Args:
            message: الرسالة
            websocket: كائن WebSocket
        """
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")
    
    async def broadcast(self, message: dict, channel: str = "default"):
        """
        بث رسالة لجميع المتصلين في قناة معينة
        
        Args:
            message: الرسالة
            channel: القناة
        """
        async with self._lock:
            if channel not in self.active_connections:
                return
            
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Failed to broadcast: {e}")
    
    async def get_connections_count(self, channel: str = None) -> int:
        """
        الحصول على عدد الاتصالات
        
        Args:
            channel: القناة (الكل إذا None)
        """
        if channel:
            return len(self.active_connections.get(channel, set()))
        
        total = 0
        for conns in self.active_connections.values():
            total += len(conns)
        return total


# إنشاء مدير الاتصالات
manager = ConnectionManager()

# إنشاء تطبيق FastAPI
app = FastAPI(title="HunterMind WebSocket API", version="1.0.0")


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """
    نقطة نهاية WebSocket الرئيسية
    
    Args:
        websocket: كائن WebSocket
        client_id: معرف العميل
    """
    channel = "default"
    await manager.connect(websocket, client_id, channel)
    
    try:
        # إرسال رسالة ترحيب
        await manager.send_personal({
            "type": "welcome",
            "message": f"Welcome {client_id}",
            "timestamp": datetime.now().isoformat()
        }, websocket)
        
        # الاستماع للرسائل
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # معالجة不同类型的 الرسائل
            await handle_message(client_id, message, websocket)
            
    except WebSocketDisconnect:
        await manager.disconnect(websocket, channel)
        await manager.broadcast({
            "type": "user_disconnected",
            "client_id": client_id,
            "timestamp": datetime.now().isoformat()
        })


@app.websocket("/ws/{client_id}/{channel}")
async def websocket_channel_endpoint(websocket: WebSocket, client_id: str, channel: str):
    """
    نقطة نهاية WebSocket مع قناة محددة
    
    Args:
        websocket: كائن WebSocket
        client_id: معرف العميل
        channel: اسم القناة
    """
    await manager.connect(websocket, client_id, channel)
    
    # إعلان الانضمام للقناة
    await manager.broadcast({
        "type": "user_joined",
        "client_id": client_id,
        "channel": channel,
        "timestamp": datetime.now().isoformat()
    }, channel)
    
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            await handle_channel_message(client_id, channel, message, websocket)
            
    except WebSocketDisconnect:
        await manager.disconnect(websocket, channel)
        await manager.broadcast({
            "type": "user_left",
            "client_id": client_id,
            "channel": channel,
            "timestamp": datetime.now().isoformat()
        }, channel)


async def handle_message(client_id: str, message: dict, websocket: WebSocket):
    """
    معالجة الرسائل الواردة
    
    Args:
        client_id: معرف العميل
        message: محتوى الرسالة
        websocket: كائن WebSocket
    """
    msg_type = message.get("type", "unknown")
    
    if msg_type == "ping":
        # الرد على ping
        await manager.send_personal({
            "type": "pong",
            "timestamp": datetime.now().isoformat()
        }, websocket)
    
    elif msg_type == "subscribe":
        # الاشتراك في قناة
        channel = message.get("channel")
        if channel:
            # سيتم التعامل معه في دالة منفصلة
            pass
    
    elif msg_type == "scan_status":
        # تحديث حالة الفحص
        await manager.broadcast({
            "type": "scan_update",
            "client_id": client_id,
            "data": message.get("data"),
            "timestamp": datetime.now().isoformat()
        })
    
    elif msg_type == "attack_result":
        # نتيجة الهجوم
        await manager.broadcast({
            "type": "attack_result",
            "client_id": client_id,
            "data": message.get("data"),
            "timestamp": datetime.now().isoformat()
        })
    
    else:
        # رسالة غير معروفة
        await manager.send_personal({
            "type": "error",
            "message": f"Unknown message type: {msg_type}",
            "timestamp": datetime.now().isoformat()
        }, websocket)


async def handle_channel_message(client_id: str, channel: str, message: dict, websocket: WebSocket):
    """
    معالجة الرسائل على قناة محددة
    
    Args:
        client_id: معرف العميل
        channel: القناة
        message: محتوى الرسالة
        websocket: كائن WebSocket
    """
    msg_type = message.get("type", "unknown")
    
    if msg_type == "chat":
        # رسالة دردشة
        await manager.broadcast({
            "type": "chat",
            "client_id": client_id,
            "channel": channel,
            "message": message.get("text"),
            "timestamp": datetime.now().isoformat()
        }, channel)
    
    elif msg_type == "command":
        # أمر للنظام
        command = message.get("command")
        
        # تنفيذ الأمر (محاكاة)
        result = {
            "type": "command_result",
            "client_id": client_id,
            "command": command,
            "result": f"Command '{command}' executed",
            "timestamp": datetime.now().isoformat()
        }
        
        await manager.send_personal(result, websocket)
    
    else:
        # بث الرسالة للقناة
        await manager.broadcast({
            "type": msg_type,
            "client_id": client_id,
            "channel": channel,
            "data": message,
            "timestamp": datetime.now().isoformat()
        }, channel)


@app.get("/ws/stats")
async def get_websocket_stats():
    """الحصول على إحصائيات WebSocket"""
    return {
        "total_connections": await manager.get_connections_count(),
        "channels": {
            channel: len(conns)
            for channel, conns in manager.active_connections.items()
        }
    }


@app.post("/ws/broadcast")
async def broadcast_message(channel: str, message: dict):
    """
    بث رسالة عبر API
    
    Args:
        channel: القناة
        message: محتوى الرسالة
    """
    await manager.broadcast(message, channel)
    return {
        "status": "sent",
        "channel": channel,
        "message": message
    }


# تشغيل الخادم
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)

