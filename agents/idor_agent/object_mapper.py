
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import logging

logger = logging.getLogger(__name__)


@dataclass
class ObjectMapping:
    """مخطط كائن"""
    object_id: str
    object_type: str  # user, order, product, document, etc.
    url: str
    parameter: Optional[str] = None
    id_type: str = "numeric"  # numeric, uuid, hash, sequential
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ObjectMapper:
    """
    مخطط الكائنات المتقدم
    
    الميزات:
    - اكتشاف الكائنات من URLs والاستجابات
    - تصنيف أنواع الكائنات
    - كشف أنماط المعرفات
    - ربط الكائنات ببعضها
    - تحليل بنية الموارد
    """
    
    # أنماط أنواع الكائنات
    OBJECT_TYPE_PATTERNS = {
        "user": [r'/user[s]?/', r'/profile', r'/account', r'/member', r'/customer'],
        "order": [r'/order[s]?/', r'/invoice', r'/purchase', r'/cart'],
        "product": [r'/product[s]?/', r'/item[s]?/', r'/goods?'],
        "document": [r'/document[s]?/', r'/file[s]?/', r'/download', r'/attachment'],
        "post": [r'/post[s]?/', r'/article[s]?/', r'/blog'],
        "comment": [r'/comment[s]?/', r'/review'],
        "message": [r'/message[s]?/', r'/inbox', r'/chat'],
        "payment": [r'/payment[s]?/', r'/transaction', r'/bill'],
        "admin": [r'/admin', r'/administrator', r'/manage'],
        "api": [r'/api/', r'/rest/', r'/v[0-9]+/'],
    }
    
    # أنماط أنواع المعرفات
    ID_TYPE_PATTERNS = {
        "numeric": r'^\d+$',
        "uuid": r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        "hash_md5": r'^[0-9a-f]{32}$',
        "hash_sha1": r'^[0-9a-f]{40}$',
        "hash_sha256": r'^[0-9a-f]{64}$',
        "base64": r'^[A-Za-z0-9+/]+=*$',
        "sequential": r'^\d+$',  # سيتم التعامل معها بشكل خاص
    }
    
    def __init__(self):
        self._object_mappings: Dict[str, List[ObjectMapping]] = {}
        
        logger.info("ObjectMapper initialized")
    
    async def map_objects_from_url(
        self,
        url: str,
        response: str = None
    ) -> List[ObjectMapping]:
        """
        رسم الكائنات من URL
        
        Args:
            url: الرابط
            response: محتوى الاستجابة (اختياري)
        
        Returns:
            قائمة بمخططات الكائنات
        """
        mappings = []
        seen = set()
        
        # تحليل URL
        parsed = urlparse(url)
        
        # 1. اكتشاف الكائنات من المسار
        path_parts = parsed.path.split('/')
        
        for i, part in enumerate(path_parts):
            # تحديد نوع الكائن
            object_type = await self._detect_object_type(part)
            
            # استخراج المعرف (إذا كان الجزء التالي رقماً)
            if i + 1 < len(path_parts):
                potential_id = path_parts[i + 1]
                id_type = await self._detect_id_type(potential_id)
                
                if id_type != "unknown":
                    mapping = ObjectMapping(
                        object_id=potential_id,
                        object_type=object_type,
                        url=url,
                        id_type=id_type
                    )
                    
                    key = f"{object_type}:{potential_id}"
                    if key not in seen:
                        seen.add(key)
                        mappings.append(mapping)
        
        # 2. اكتشاف الكائنات من معاملات URL
        params = parse_qs(parsed.query)
        for param_name, param_values in params.items():
            object_type = await self._detect_object_type(param_name)
            
            for value in param_values:
                id_type = await self._detect_id_type(value)
                
                if id_type != "unknown":
                    mapping = ObjectMapping(
                        object_id=value,
                        object_type=object_type,
                        url=url,
                        parameter=param_name,
                        id_type=id_type
                    )
                    
                    key = f"{object_type}:{value}"
                    if key not in seen:
                        seen.add(key)
                        mappings.append(mapping)
        
        # 3. اكتشاف الكائنات من الاستجابة
        if response:
            response_mappings = await self._map_objects_from_response(response, url)
            for mapping in response_mappings:
                key = f"{mapping.object_type}:{mapping.object_id}"
                if key not in seen:
                    seen.add(key)
                    mappings.append(mapping)
        
        # تخزين النتائج
        if url not in self._object_mappings:
            self._object_mappings[url] = []
        self._object_mappings[url].extend(mappings)
        
        logger.info(f"Mapped {len(mappings)} objects from {url}")
        return mappings
    
    async def _map_objects_from_response(
        self,
        response: str,
        url: str
    ) -> List[ObjectMapping]:
        """
        رسم الكائنات من محتوى الاستجابة
        
        Args:
            response: محتوى الاستجابة
            url: الرابط الأساسي
        
        Returns:
            قائمة بمخططات الكائنات
        """
        mappings = []
        seen = set()
        
        # البحث عن JSON objects
        json_pattern = re.compile(r'\{[^{}]*"id"\s*:\s*"?\d+"?[^{}]*\}')
        for match in json_pattern.finditer(response):
            try:
                obj = json.loads(match.group())
                if "id" in obj:
                    obj_id = str(obj["id"])
                    obj_type = "unknown"
                    
                    # تحديد النوع من المفاتيح
                    for key in obj.keys():
                        detected_type = await self._detect_object_type(key)
                        if detected_type != "unknown":
                            obj_type = detected_type
                            break
                    
                    id_type = await self._detect_id_type(obj_id)
                    
                    mapping = ObjectMapping(
                        object_id=obj_id,
                        object_type=obj_type,
                        url=url,
                        id_type=id_type,
                        metadata={"source": "json_response"}
                    )
                    
                    key = f"{obj_type}:{obj_id}"
                    if key not in seen:
                        seen.add(key)
                        mappings.append(mapping)
                        
            except json.JSONDecodeError:
                pass
        
        # البحث عن href links
        link_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.I)
        for match in link_pattern.finditer(response):
            link = match.group(1)
            if link.startswith('/') or link.startswith('http'):
                parsed = urlparse(link)
                path = parsed.path
                
                # البحث عن أرقام في المسار
                numbers = re.findall(r'\b\d{3,}\b', path)
                for num in numbers:
                    obj_type = await self._detect_object_type(path)
                    mapping = ObjectMapping(
                        object_id=num,
                        object_type=obj_type,
                        url=link,
                        id_type="numeric",
                        metadata={"source": "href", "full_url": link}
                    )
                    
                    key = f"{obj_type}:{num}"
                    if key not in seen:
                        seen.add(key)
                        mappings.append(mapping)
        
        return mappings
    
    async def _detect_object_type(self, text: str) -> str:
        """
        اكتشاف نوع الكائن من النص
        
        Args:
            text: النص للتحليل
        
        Returns:
            نوع الكائن
        """
        text_lower = text.lower()
        
        for obj_type, patterns in self.OBJECT_TYPE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    return obj_type
        
        return "unknown"
    
    async def _detect_id_type(self, id_str: str) -> str:
        """
        اكتشاف نوع المعرف
        
        Args:
            id_str: المعرف
        
        Returns:
            نوع المعرف
        """
        for id_type, pattern in self.ID_TYPE_PATTERNS.items():
            if re.match(pattern, id_str, re.I):
                # التحقق من التسلسل العددي
                if id_type == "numeric" and id_str.isdigit():
                    num = int(id_str)
                    # الأرقام الصغيرة قد تكون تسلسلية
                    if 1 <= num <= 10000:
                        return "sequential"
                return id_type
        
        return "unknown"
    
    async def get_object_hierarchy(
        self,
        url: str,
        object_id: str
    ) -> Dict[str, Any]:
        """
        الحصول على هيكل الكائن والكائنات المرتبطة به
        
        Args:
            url: الرابط
            object_id: معرف الكائن
        
        Returns:
            هيكل الكائن
        """
        hierarchy = {
            "object_id": object_id,
            "parent_objects": [],
            "child_objects": [],
            "related_objects": []
        }
        
        # البحث عن الكائنات المرتبطة في نفس URL
        if url in self._object_mappings:
            for mapping in self._object_mappings[url]:
                if mapping.object_id != object_id:
                    hierarchy["related_objects"].append({
                        "id": mapping.object_id,
                        "type": mapping.object_type,
                        "parameter": mapping.parameter
                    })
        
        # استخراج العلاقات من المعرف (مثلاً user_123 -> user, 123)
        if "_" in object_id:
            parts = object_id.split('_')
            if len(parts) == 2 and parts[1].isdigit():
                hierarchy["parent_objects"].append({
                    "id": parts[1],
                    "type": parts[0]
                })
        
        return hierarchy
    
    async def get_all_objects(self, url: str = None) -> List[ObjectMapping]:
        """
        الحصول على جميع الكائنات المكتشفة
        
        Args:
            url: رابط محدد (الكل إذا None)
        
        Returns:
            قائمة بمخططات الكائنات
        """
        if url:
            return self._object_mappings.get(url, [])
        
        all_objects = []
        for objects in self._object_mappings.values():
            all_objects.extend(objects)
        return all_objects
    
    async def get_objects_by_type(
        self,
        object_type: str,
        url: str = None
    ) -> List[ObjectMapping]:
        """
        الحصول على الكائنات حسب النوع
        
        Args:
            object_type: نوع الكائن
            url: رابط محدد (الكل إذا None)
        
        Returns:
            قائمة بمخططات الكائنات
        """
        all_objects = await self.get_all_objects(url)
        return [obj for obj in all_objects if obj.object_type == object_type]
    
    async def get_sequential_ids(self, url: str = None) -> List[ObjectMapping]:
        """
        الحصول على المعرفات التسلسلية
        
        Args:
            url: رابط محدد (الكل إذا None)
        
        Returns:
            قائمة بالكائنات ذات المعرفات التسلسلية
        """
        all_objects = await self.get_all_objects(url)
        return [obj for obj in all_objects if obj.id_type == "sequential"]
    
    async def get_statistics(self) -> Dict:
        """إحصائيات المخطط"""
        all_objects = await self.get_all_objects()
        
        # إحصائيات حسب النوع
        type_stats = {}
        for obj in all_objects:
            type_stats[obj.object_type] = type_stats.get(obj.object_type, 0) + 1
        
        # إحصائيات حسب نوع المعرف
        id_type_stats = {}
        for obj in all_objects:
            id_type_stats[obj.id_type] = id_type_stats.get(obj.id_type, 0) + 1
        
        return {
            "total_urls": len(self._object_mappings),
            "total_objects": len(all_objects),
            "avg_objects_per_url": len(all_objects) / len(self._object_mappings) if self._object_mappings else 0,
            "by_type": type_stats,
            "by_id_type": id_type_stats,
            "sequential_count": len(await self.get_sequential_ids()),
            "object_types_supported": len(self.OBJECT_TYPE_PATTERNS)
        }
    
    async def clear_mappings(self, url: str = None):
        """مسح المخططات"""
        if url:
            self._object_mappings.pop(url, None)
        else:
            self._object_mappings.clear()
        
        logger.info(f"Object mappings cleared for {url if url else 'all targets'}")

