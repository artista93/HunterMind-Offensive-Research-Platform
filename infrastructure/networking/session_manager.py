

import json
import os
import time
import asyncio
import uuid
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class SessionStatus(Enum):
    """حالة الجلسة"""
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALID = "invalid"
    ROTATED = "rotated"
    BANNED = "banned"


@dataclass
class Session:
    """جلسة مستخدم"""
    id: str
    name: str
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    tokens: Dict[str, str] = field(default_factory=dict)
    storage_state: Optional[Dict] = None
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    usage_count: int = 0
    status: SessionStatus = SessionStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """تحويل الجلسة إلى قاموس"""
        return {
            "id": self.id,
            "name": self.name,
            "cookies": self.cookies,
            "headers": self.headers,
            "tokens": self.tokens,
            "storage_state": self.storage_state,
            "created_at": self.created_at,
            "last_used": self.last_used,
            "usage_count": self.usage_count,
            "status": self.status.value,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Session':
        """إنشاء جلسة من قاموس"""
        return cls(
            id=data["id"],
            name=data["name"],
            cookies=data.get("cookies", []),
            headers=data.get("headers", {}),
            tokens=data.get("tokens", {}),
            storage_state=data.get("storage_state"),
            created_at=data.get("created_at", time.time()),
            last_used=data.get("last_used", time.time()),
            usage_count=data.get("usage_count", 0),
            status=SessionStatus(data.get("status", "active")),
            metadata=data.get("metadata", {})
        )
    
    def record_usage(self):
        """تسجيل استخدام الجلسة"""
        self.usage_count += 1
        self.last_used = time.time()
    
    def is_expired(self, max_age: int = 3600) -> bool:
        """هل انتهت صلاحية الجلسة؟"""
        return time.time() - self.created_at > max_age
    
    def add_cookie(self, cookie: Dict):
        """إضافة كوكي"""
        self.cookies.append(cookie)
    
    def add_header(self, key: str, value: str):
        """إضافة header"""
        self.headers[key] = value
    
    def add_token(self, token_type: str, token_value: str):
        """إضافة توكن"""
        self.tokens[token_type] = token_value


class SessionManager:
    """مدير الجلسات المتقدم"""
    
    def __init__(self, storage_path: str = "data/sessions.json"):
        self.storage_path = storage_path
        self._sessions: Dict[str, Session] = {}
        self._current_session_id: Optional[str] = None
        self._session_lock = asyncio.Lock()
        self._default_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        self._load_sessions()
    
    def _load_sessions(self):
        """تحميل الجلسات من ملف"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    data = json.load(f)
                    for session_data in data.get("sessions", []):
                        session = Session.from_dict(session_data)
                        self._sessions[session.id] = session
                    self._current_session_id = data.get("current_session")
            except Exception as e:
                print(f"Failed to load sessions: {e}")
    
    def _save_sessions(self):
        """حفظ الجلسات إلى ملف"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
        try:
            data = {
                "sessions": [s.to_dict() for s in self._sessions.values()],
                "current_session": self._current_session_id,
                "updated_at": time.time()
            }
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to save sessions: {e}")
    
    async def create_session(self, name: str = None) -> Session:
        """إنشاء جلسة جديدة"""
        async with self._session_lock:
            session_id = str(uuid.uuid4())[:8]
            session_name = name or f"session_{session_id}"
            
            session = Session(
                id=session_id,
                name=session_name,
                headers=self._default_headers.copy()
            )
            self._sessions[session_id] = session
            self._save_sessions()
            return session
    
    async def get_session(self, session_id: str) -> Optional[Session]:
        """الحصول على جلسة بالمعرف"""
        async with self._session_lock:
            return self._sessions.get(session_id)
    
    async def get_current_session(self) -> Optional[Session]:
        """الحصول على الجلسة الحالية"""
        async with self._session_lock:
            if self._current_session_id:
                return self._sessions.get(self._current_session_id)
            return None
    
    async def set_current_session(self, session_id: str) -> bool:
        """تعيين الجلسة الحالية"""
        async with self._session_lock:
            if session_id in self._sessions:
                self._current_session_id = session_id
                self._save_sessions()
                return True
            return False
    
    async def update_session(self, session_id: str, **kwargs) -> bool:
        """تحديث الجلسة"""
        async with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            
            for key, value in kwargs.items():
                if hasattr(session, key):
                    setattr(session, key, value)
            
            session.record_usage()
            self._save_sessions()
            return True
    
    async def add_cookies(self, session_id: str, cookies: List[Dict]) -> bool:
        """إضافة كوكيز إلى الجلسة"""
        async with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            
            for cookie in cookies:
                session.add_cookie(cookie)
            
            session.record_usage()
            self._save_sessions()
            return True
    
    async def get_cookies(self, session_id: str = None) -> List[Dict]:
        """الحصول على كوكيز الجلسة"""
        sid = session_id or self._current_session_id
        if not sid:
            return []
        
        async with self._session_lock:
            session = self._sessions.get(sid)
            if not session:
                return []
            return session.cookies.copy()
    
    async def get_headers(self, session_id: str = None) -> Dict:
        """الحصول على headers الجلسة"""
        sid = session_id or self._current_session_id
        if not sid:
            return self._default_headers.copy()
        
        async with self._session_lock:
            session = self._sessions.get(sid)
            if not session:
                return self._default_headers.copy()
            return session.headers.copy()
    
    async def update_headers(self, session_id: str, headers: Dict) -> bool:
        """تحديث headers الجلسة"""
        async with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            
            session.headers.update(headers)
            session.record_usage()
            self._save_sessions()
            return True
    
    async def add_token(self, session_id: str, token_type: str, token_value: str) -> bool:
        """إضافة توكن إلى الجلسة"""
        async with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            
            session.add_token(token_type, token_value)
            
            # إضافة التوكن إلى الـ headers تلقائياً
            if token_type.lower() == "bearer":
                session.headers["Authorization"] = f"Bearer {token_value}"
            elif token_type.lower() == "basic":
                session.headers["Authorization"] = f"Basic {token_value}"
            elif token_type.lower() == "csrf":
                session.headers["X-CSRF-Token"] = token_value
                session.headers["CSRF-Token"] = token_value
            
            session.record_usage()
            self._save_sessions()
            return True
    
    async def get_token(self, session_id: str, token_type: str) -> Optional[str]:
        """الحصول على توكن من الجلسة"""
        async with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            return session.tokens.get(token_type)
    
    async def rotate_session(self, session_id: str) -> Optional[Session]:
        """تناوب الجلسة (إنشاء جلسة جديدة من بيانات الجلسة الحالية)"""
        async with self._session_lock:
            old_session = self._sessions.get(session_id)
            if not old_session:
                return None
            
            # إنشاء جلسة جديدة بنفس البيانات
            new_session = Session(
                id=str(uuid.uuid4())[:8],
                name=f"{old_session.name}_rotated",
                cookies=old_session.cookies.copy(),
                headers=old_session.headers.copy(),
                tokens=old_session.tokens.copy(),
                storage_state=old_session.storage_state,
                metadata=old_session.metadata.copy()
            )
            
            # تحديث حالة الجلسة القديمة
            old_session.status = SessionStatus.ROTATED
            
            self._sessions[new_session.id] = new_session
            
            if self._current_session_id == session_id:
                self._current_session_id = new_session.id
            
            self._save_sessions()
            return new_session
    
    async def invalidate_session(self, session_id: str) -> bool:
        """إبطال الجلسة"""
        async with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return False
            
            session.status = SessionStatus.INVALID
            
            if self._current_session_id == session_id:
                self._current_session_id = None
            
            self._save_sessions()
            return True
    
    async def list_sessions(self) -> List[Dict]:
        """قائمة جميع الجلسات"""
        async with self._session_lock:
            return [
                {
                    "id": s.id,
                    "name": s.name,
                    "status": s.status.value,
                    "usage_count": s.usage_count,
                    "created_at": s.created_at,
                    "last_used": s.last_used,
                    "cookies_count": len(s.cookies),
                    "tokens_count": len(s.tokens)
                }
                for s in self._sessions.values()
            ]
    
    async def cleanup_expired_sessions(self, max_age: int = 86400) -> int:
        """تنظيف الجلسات المنتهية (أقدم من max_age ثانية)"""
        async with self._session_lock:
            expired = []
            for sid, session in self._sessions.items():
                if session.is_expired(max_age):
                    expired.append(sid)
            
            for sid in expired:
                del self._sessions[sid]
            
            if self._current_session_id in expired:
                self._current_session_id = None
            
            self._save_sessions()
            return len(expired)
    
    async def export_session(self, session_id: str, filepath: str = None) -> Optional[str]:
        """تصدير الجلسة إلى ملف"""
        async with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            
            if not filepath:
                filepath = f"data/export_session_{session_id}.json"
            
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
            
            return filepath
    
    async def import_session(self, filepath: str) -> Optional[Session]:
        """استيراد جلسة من ملف"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            session = Session.from_dict(data)
            
            async with self._session_lock:
                self._sessions[session.id] = session
                self._save_sessions()
            
            return session
        except Exception as e:
            print(f"Failed to import session: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """إحصائيات الجلسات"""
        active = sum(1 for s in self._sessions.values() if s.status == SessionStatus.ACTIVE)
        total = len(self._sessions)
        
        return {
            "total_sessions": total,
            "active_sessions": active,
            "current_session": self._current_session_id,
            "storage_path": self.storage_path,
            "avg_usage": sum(s.usage_count for s in self._sessions.values()) / max(1, total)
        }


# نسخة عالمية
_default_session_manager = None


async def get_session_manager() -> SessionManager:
    """الحصول على نسخة عالمية من مدير الجلسات"""
    global _default_session_manager
    if _default_session_manager is None:
        _default_session_manager = SessionManager()
    return _default_session_manager

