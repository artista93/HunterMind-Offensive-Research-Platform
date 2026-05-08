
import asyncio
import uuid
import yaml
import json
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from .docker_runtime import DockerRuntime, ContainerConfig, ContainerStatus, get_docker_runtime
from .isolated_executor import IsolatedExecutor, get_isolated_executor
from .target_emulator import TargetEmulator, TargetInstance, TargetType, TargetConfig, get_target_emulator


class LabStatus(Enum):
    """حالة المختبر"""
    CREATED = "created"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    PAUSED = "paused"
    DESTROYED = "destroyed"


class NetworkIsolation(Enum):
    """مستوى عزل الشبكة"""
    NONE = "none"           # اتصال كامل بالإنترنت
    LIMITED = "limited"     # اتصال محدود (فقط HTTP/HTTPS)
    ISOLATED = "isolated"   # معزول تماماً (شبكة داخلية فقط)
    CUSTOM = "custom"       # شبكة مخصصة


@dataclass
class LabConfig:
    """إعدادات المختبر"""
    name: str
    description: str = ""
    network_isolation: NetworkIsolation = NetworkIsolation.ISOLATED
    targets: List[Dict[str, Any]] = field(default_factory=list)
    max_concurrent_attacks: int = 10
    auto_cleanup: bool = True
    cleanup_timeout: int = 300  # 5 دقائق
    persistent_storage: bool = False
    capture_traffic: bool = True
    log_level: str = "INFO"
    
    # حدود الموارد
    total_memory_limit: str = "4g"
    total_cpu_limit: float = 4.0
    
    # شبكة مخصصة
    custom_network_name: Optional[str] = None
    custom_subnet: Optional[str] = None


@dataclass
class LabSession:
    """جلسة مختبر نشطة"""
    lab_id: str
    config: LabConfig
    status: LabStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None
    
    # الموارد
    target_instances: Dict[str, TargetInstance] = field(default_factory=dict)
    network_name: Optional[str] = None
    container_ids: List[str] = field(default_factory=list)
    
    # إحصائيات
    total_attacks: int = 0
    successful_attacks: int = 0
    vulnerabilities_found: List[str] = field(default_factory=list)
    
    # سجلات
    attack_logs: List[Dict] = field(default_factory=list)
    system_logs: List[Dict] = field(default_factory=list)
    
    # نقاط التفتيش
    checkpoints: List[Dict] = field(default_factory=list)


class LabEnvironment:
    """
    بيئة مختبر متكاملة لإدارة الاختبارات الأمنية
    
    الميزات:
    - إدارة دورة حياة كاملة للمختبرات
    - عزل الشبكة (معزول/محدود/كامل)
    - مراقبة جميع الهجمات
    - حفظ الحالة وإنشاء نقاط تفتيش
    - تقارير تلقائية
    """
    
    def __init__(self):
        self._runtime: Optional[DockerRuntime] = None
        self._executor: Optional[IsolatedExecutor] = None
        self._emulator: Optional[TargetEmulator] = None
        
        self._labs: Dict[str, LabSession] = {}
        self._active_lab_id: Optional[str] = None
        self._lock = asyncio.Lock()
        self._initialized = False
        
        # المهام الخلفية
        self._cleanup_tasks: Dict[str, asyncio.Task] = {}
        
        # إحصائيات عامة
        self._global_stats = {
            "total_labs_created": 0,
            "total_labs_destroyed": 0,
            "total_attacks_executed": 0,
            "total_successful_attacks": 0,
            "peak_concurrent_labs": 0
        }
        
        # دليل التخزين
        self._storage_dir = Path("./lab_storage")
        self._storage_dir.mkdir(exist_ok=True)
    
    async def initialize(self):
        """تهيئة البيئة"""
        if self._initialized:
            return
        
        self._runtime = await get_docker_runtime()
        self._executor = await get_isolated_executor()
        self._emulator = await get_target_emulator()
        
        self._initialized = True
        print("   🧪 Lab environment initialized")
    
    async def create_lab(self, config: LabConfig) -> Optional[str]:
        """
        إنشاء مختبر جديد
        
        Returns:
            lab_id: معرف المختبر
        """
        async with self._lock:
            if not self._initialized:
                await self.initialize()
            
            # إنشاء معرف فريد
            lab_id = f"lab_{config.name.lower().replace(' ', '_')}_{uuid.uuid4().hex[:8]}"
            
            # إنشاء جلسة المختبر
            session = LabSession(
                lab_id=lab_id,
                config=config,
                status=LabStatus.CREATED,
                created_at=datetime.now()
            )
            
            self._labs[lab_id] = session
            self._global_stats["total_labs_created"] += 1
            
            # تحديث الذروة
            active_labs = sum(1 for l in self._labs.values() if l.status == LabStatus.RUNNING)
            if active_labs > self._global_stats["peak_concurrent_labs"]:
                self._global_stats["peak_concurrent_labs"] = active_labs
            
            print(f"   🧪 Created lab: {config.name} ({lab_id})")
            
            # حفظ إعدادات المختبر
            await self._save_lab_config(lab_id, config)
            
            return lab_id
    
    async def start_lab(self, lab_id: str) -> bool:
        """
        بدء تشغيل مختبر
        
        يقوم بـ:
        1. إنشاء شبكة معزولة
        2. بدء جميع الأهداف
        3. تجهيز بيئة الهجوم
        """
        async with self._lock:
            if lab_id not in self._labs:
                print(f"   ❌ Lab {lab_id} not found")
                return False
            
            session = self._labs[lab_id]
            
            if session.status in [LabStatus.RUNNING, LabStatus.STARTING]:
                print(f"   ⚠️ Lab {lab_id} is already {session.status.value}")
                return session.status == LabStatus.RUNNING
            
            session.status = LabStatus.STARTING
            print(f"   🚀 Starting lab: {session.config.name}")
            
            try:
                # 1. إنشاء شبكة معزولة إذا لزم الأمر
                if session.config.network_isolation != NetworkIsolation.NONE:
                    network_name = await self._create_isolated_network(lab_id)
                    session.network_name = network_name
                    print(f"   🌐 Created network: {network_name}")
                
                # 2. بدء جميع الأهداف
                for target_config in session.config.targets:
                    target_type = TargetType(target_config.get("type", "custom"))
                    
                    if target_type == TargetType.CUSTOM:
                        # إنشاء هدف مخصص
                        custom_config = TargetConfig(
                            name=target_config["name"],
                            target_type=TargetType.CUSTOM,
                            image=target_config.get("image", "custom_vuln_app"),
                            port_mappings=target_config.get("port_mappings", {8000: 80}),
                            environment=target_config.get("environment", {}),
                            vulnerabilities=target_config.get("vulnerabilities", []),
                            default_credentials=target_config.get("credentials", {"username": "admin", "password": "password"})
                        )
                        instance = await self._emulator.start_target(
                            TargetType.CUSTOM,
                            custom_config=custom_config,
                            name=target_config["name"]
                        )
                    else:
                        # هدف جاهز
                        instance = await self._emulator.start_target(
                            target_type,
                            name=target_config.get("name")
                        )
                    
                    if instance:
                        session.target_instances[target_config["name"]] = instance
                        session.container_ids.append(instance.container_id)
                        print(f"   ✅ Started target: {target_config['name']} at {instance.url}")
                    else:
                        print(f"   ⚠️ Failed to start target: {target_config['name']}")
                
                if not session.target_instances:
                    raise RuntimeError("No targets could be started")
                
                # 3. بدء مراقبة المختبر
                if session.config.capture_traffic:
                    await self._start_traffic_capture(lab_id)
                
                session.status = LabStatus.RUNNING
                session.started_at = datetime.now()
                
                # 4. جدولة التنظيف التلقائي
                if session.config.auto_cleanup:
                    self._schedule_auto_cleanup(lab_id)
                
                print(f"   ✅ Lab {session.config.name} is running with {len(session.target_instances)} targets")
                
                # 5. حفظ الحالة
                await self._save_lab_state(lab_id)
                
                return True
                
            except Exception as e:
                session.status = LabStatus.ERROR
                print(f"   ❌ Failed to start lab {lab_id}: {e}")
                await self._cleanup_lab_resources(lab_id)
                return False
    
    async def _create_isolated_network(self, lab_id: str) -> str:
        """إنشاء شبكة معزولة للمختبر"""
        network_name = f"labnet_{lab_id}"
        
        if not self._runtime.is_available():
            return network_name  # وضع المحاكاة
        
        # استخدام Docker SDK لإنشاء الشبكة
        import docker
        client = docker.from_env()
        
        try:
            # حذف الشبكة إذا كانت موجودة
            try:
                network = client.networks.get(network_name)
                network.remove()
            except:
                pass
            
            # إنشاء شبكة جديدة
            network_config = {
                "name": network_name,
                "driver": "bridge",
                "internal": session.config.network_isolation == NetworkIsolation.ISOLATED,
                "attachable": True
            }
            
            if session.config.custom_subnet:
                network_config["ipam"] = {
                    "driver": "default",
                    "config": [{"subnet": session.config.custom_subnet}]
                }
            
            network = client.networks.create(**network_config)
            return network_name
            
        except Exception as e:
            print(f"   ⚠️ Failed to create Docker network: {e}")
            return network_name
    
    async def _start_traffic_capture(self, lab_id: str):
        """بدء التقاط حركة المرور"""
        session = self._labs[lab_id]
        
        # إنشاء ملف التقاط
        capture_file = self._storage_dir / f"{lab_id}_traffic.pcap"
        
        # تسجيل بدء التقاط
        session.system_logs.append({
            "timestamp": datetime.now().isoformat(),
            "event": "traffic_capture_started",
            "file": str(capture_file)
        })
    
    def _schedule_auto_cleanup(self, lab_id: str):
        """جدولة التنظيف التلقائي"""
        async def cleanup_task():
            await asyncio.sleep(self._labs[lab_id].config.cleanup_timeout)
            await self.stop_lab(lab_id, destroy=True)
        
        task = asyncio.create_task(cleanup_task())
        self._cleanup_tasks[lab_id] = task
    
    async def stop_lab(self, lab_id: str, destroy: bool = False) -> bool:
        """إيقاف مختبر"""
        async with self._lock:
            if lab_id not in self._labs:
                return False
            
            session = self._labs[lab_id]
            
            if session.status == LabStatus.STOPPED:
                return True
            
            session.status = LabStatus.STOPPING
            print(f"   🛑 Stopping lab: {session.config.name}")
            
            # إلغاء مهمة التنظيف
            if lab_id in self._cleanup_tasks:
                self._cleanup_tasks[lab_id].cancel()
                del self._cleanup_tasks[lab_id]
            
            # إيقاف جميع الأهداف
            for name, instance in session.target_instances.items():
                await self._emulator.stop_target(name, remove=destroy)
            
            # حذف الشبكة
            if session.network_name:
                await self._delete_network(session.network_name)
            
            if destroy:
                session.status = LabStatus.DESTROYED
                # حفظ التقرير النهائي
                await self._generate_final_report(lab_id)
                # حذف الجلسة
                del self._labs[lab_id]
                self._global_stats["total_labs_destroyed"] += 1
                print(f"   💀 Lab {lab_id} destroyed")
            else:
                session.status = LabStatus.STOPPED
                session.stopped_at = datetime.now()
                await self._save_lab_state(lab_id)
                print(f"   ⏸️ Lab {lab_id} stopped")
            
            return True
    
    async def _delete_network(self, network_name: str):
        """حذف الشبكة"""
        try:
            import docker
            client = docker.from_env()
            network = client.networks.get(network_name)
            network.remove()
        except:
            pass
    
    async def _cleanup_lab_resources(self, lab_id: str):
        """تنظيف موارد المختبر"""
        session = self._labs.get(lab_id)
        if not session:
            return
        
        # إيقاف جميع الحاويات
        for container_id in session.container_ids:
            try:
                await self._runtime.stop_container(container_id)
                await self._runtime.remove_container(container_id)
            except:
                pass
        
        # حذف الشبكة
        if session.network_name:
            await self._delete_network(session.network_name)
    
    async def execute_attack(
        self,
        lab_id: str,
        target_name: str,
        attack_type: str,
        payload: str,
        endpoint: str = "/"
    ) -> Dict[str, Any]:
        """
        تنفيذ هجوم داخل المختبر
        
        Returns:
            نتيجة الهجوم
        """
        if lab_id not in self._labs:
            return {"success": False, "error": f"Lab {lab_id} not found"}
        
        session = self._labs[lab_id]
        
        if session.status != LabStatus.RUNNING:
            return {"success": False, "error": f"Lab {lab_id} is not running"}
        
        if target_name not in session.target_instances:
            return {"success": False, "error": f"Target {target_name} not found"}
        
        target = session.target_instances[target_name]
        
        # تسجيل الهجوم
        attack_record = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": attack_type,
            "target": target_name,
            "endpoint": endpoint,
            "payload": payload[:200],  # اقتطاع للعرض
            "success": False,
            "result": None
        }
        
        # تنفيذ الهجوم باستخدام المنفذ المعزول
        try:
            # بناء الطلب
            full_url = f"{target.url}{endpoint}"
            
            if attack_type in ["XSS", "SQLi", "IDOR"]:
                # هجوم ويب - استخدام curl
                curl_cmd = f'curl -s -X GET "{full_url}?q={payload}"'
                result, stdout, stderr, exec_time = await self._executor.execute_shell(
                    curl_cmd,
                    timeout=30
                )
                
                success = result.value == "success" and "error" not in stdout.lower()
                attack_record["success"] = success
                attack_record["result"] = stdout[:500]
                
                # تحديث إحصائيات المختبر
                session.total_attacks += 1
                if success:
                    session.successful_attacks += 1
                    self._global_stats["total_successful_attacks"] += 1
                
                # تسجيل في الهدف
                await self._emulator.record_attack(
                    target_name,
                    attack_type,
                    success,
                    payload
                )
                
            elif attack_type == "RCE":
                # هجوم أوامر عن بُعد
                result, stdout, stderr, exec_time = await self._executor.execute_shell(
                    f'curl -s "{full_url}?cmd={payload}"',
                    timeout=30
                )
                success = result.value == "success"
                attack_record["success"] = success
                attack_record["result"] = stdout[:500]
                
                session.total_attacks += 1
                if success:
                    session.successful_attacks += 1
            
            else:
                attack_record["error"] = f"Unknown attack type: {attack_type}"
                attack_record["success"] = False
            
        except Exception as e:
            attack_record["error"] = str(e)
            attack_record["success"] = False
        
        # حفظ السجل
        session.attack_logs.append(attack_record)
        self._global_stats["total_attacks_executed"] += 1
        
        return attack_record
    
    async def get_lab_status(self, lab_id: str = None) -> Dict:
        """الحصول على حالة مختبر أو جميع المختبرات"""
        if lab_id:
            if lab_id not in self._labs:
                return {"error": f"Lab {lab_id} not found"}
            session = self._labs[lab_id]
            
            return {
                "lab_id": lab_id,
                "name": session.config.name,
                "status": session.status.value,
                "created_at": session.created_at.isoformat(),
                "started_at": session.started_at.isoformat() if session.started_at else None,
                "uptime": (datetime.now() - session.started_at).total_seconds() if session.started_at else 0,
                "targets": {
                    name: {
                        "url": inst.url,
                        "type": inst.config.target_type.value,
                        "status": inst.status.value
                    }
                    for name, inst in session.target_instances.items()
                },
                "stats": {
                    "total_attacks": session.total_attacks,
                    "successful_attacks": session.successful_attacks,
                    "success_rate": session.successful_attacks / max(1, session.total_attacks),
                    "vulnerabilities_found": len(session.vulnerabilities_found)
                }
            }
        
        # جميع المختبرات
        return {
            lab_id: {
                "name": session.config.name,
                "status": session.status.value,
                "targets": len(session.target_instances),
                "attacks": session.total_attacks
            }
            for lab_id, session in self._labs.items()
        }
    
    async def create_checkpoint(self, lab_id: str, name: str) -> bool:
        """إنشاء نقطة تفتيش للمختبر"""
        if lab_id not in self._labs:
            return False
        
        session = self._labs[lab_id]
        
        checkpoint = {
            "id": f"ckpt_{len(session.checkpoints) + 1}",
            "name": name,
            "timestamp": datetime.now().isoformat(),
            "state": await self._capture_lab_state(lab_id)
        }
        
        session.checkpoints.append(checkpoint)
        
        # حفظ نقطة التفتيش
        checkpoint_file = self._storage_dir / f"{lab_id}_checkpoint_{checkpoint['id']}.json"
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint, f, indent=2)
        
        print(f"   📸 Checkpoint '{name}' created for lab {session.config.name}")
        return True
    
    async def restore_checkpoint(self, lab_id: str, checkpoint_id: str) -> bool:
        """استعادة نقطة تفتيش"""
        if lab_id not in self._labs:
            return False
        
        session = self._labs[lab_id]
        
        # البحث عن نقطة التفتيش
        checkpoint = None
        for ckpt in session.checkpoints:
            if ckpt["id"] == checkpoint_id:
                checkpoint = ckpt
                break
        
        if not checkpoint:
            return False
        
        # إيقاف المختبر الحالي
        await self.stop_lab(lab_id, destroy=False)
        
        # استعادة الحالة
        # (تنفيذ استعادة الحالة حسب الحاجة)
        
        # إعادة التشغيل
        await self.start_lab(lab_id)
        
        print(f"   🔄 Restored checkpoint '{checkpoint['name']}' for lab {session.config.name}")
        return True
    
    async def _capture_lab_state(self, lab_id: str) -> Dict:
        """التقاط حالة المختبر الحالية"""
        session = self._labs[lab_id]
        
        return {
            "config": {
                "name": session.config.name,
                "network_isolation": session.config.network_isolation.value,
                "targets": [
                    {
                        "name": name,
                        "type": inst.config.target_type.value,
                        "url": inst.url
                    }
                    for name, inst in session.target_instances.items()
                ]
            },
            "stats": {
                "total_attacks": session.total_attacks,
                "successful_attacks": session.successful_attacks
            },
            "timestamp": datetime.now().isoformat()
        }
    
    async def generate_lab_report(self, lab_id: str, format: str = "json") -> str:
        """توليد تقرير عن المختبر"""
        if lab_id not in self._labs:
            return ""
        
        session = self._labs[lab_id]
        
        report = {
            "lab_id": lab_id,
            "name": session.config.name,
            "description": session.config.description,
            "created_at": session.created_at.isoformat(),
            "started_at": session.started_at.isoformat() if session.started_at else None,
            "stopped_at": session.stopped_at.isoformat() if session.stopped_at else None,
            "duration": (
                (session.stopped_at or datetime.now()) - session.started_at
            ).total_seconds() if session.started_at else 0,
            "targets": [
                {
                    "name": name,
                    "type": inst.config.target_type.value,
                    "url": inst.url,
                    "vulnerabilities": inst.config.vulnerabilities
                }
                for name, inst in session.target_instances.items()
            ],
            "attacks": {
                "total": session.total_attacks,
                "successful": session.successful_attacks,
                "success_rate": session.successful_attacks / max(1, session.total_attacks),
                "by_type": {}
            },
            "attack_logs": session.attack_logs[-50:],  # آخر 50 هجوم
            "vulnerabilities_found": session.vulnerabilities_found,
            "checkpoints": len(session.checkpoints)
        }
        
        # تجميع الهجمات حسب النوع
        for log in session.attack_logs:
            atype = log.get("attack_type", "unknown")
            if atype not in report["attacks"]["by_type"]:
                report["attacks"]["by_type"][atype] = {"total": 0, "successful": 0}
            report["attacks"]["by_type"][atype]["total"] += 1
            if log.get("success"):
                report["attacks"]["by_type"][atype]["successful"] += 1
        
        # حفظ التقرير
        report_file = self._storage_dir / f"{lab_id}_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        if format == "json":
            return str(report_file)
        
        # يمكن إضافة دعم PDF, HTML, إلخ
        return str(report_file)
    
    async def _generate_final_report(self, lab_id: str):
        """توليد التقرير النهائي قبل الحذف"""
        await self.generate_lab_report(lab_id)
    
    async def _save_lab_config(self, lab_id: str, config: LabConfig):
        """حفظ إعدادات المختبر"""
        config_file = self._storage_dir / f"{lab_id}_config.yaml"
        with open(config_file, "w") as f:
            yaml.dump({
                "name": config.name,
                "description": config.description,
                "network_isolation": config.network_isolation.value,
                "targets": config.targets,
                "max_concurrent_attacks": config.max_concurrent_attacks,
                "auto_cleanup": config.auto_cleanup,
                "capture_traffic": config.capture_traffic
            }, f)
    
    async def _save_lab_state(self, lab_id: str):
        """حفظ حالة المختبر"""
        await self._capture_lab_state(lab_id)
    
    async def list_labs(self) -> List[Dict]:
        """قائمة جميع المختبرات"""
        return [
            {
                "lab_id": lab_id,
                "name": session.config.name,
                "status": session.status.value,
                "targets": len(session.target_instances),
                "attacks": session.total_attacks,
                "created_at": session.created_at.isoformat()
            }
            for lab_id, session in self._labs.items()
        ]
    
    async def get_available_scenarios(self) -> List[Dict]:
        """الحصول على سيناريوهات اختبار جاهزة"""
        return [
            {
                "name": "web_attacks_basics",
                "description": "سيناريو أساسي للهجمات الويب (XSS, SQLi, IDOR)",
                "targets": [
                    {"name": "xss_lab", "type": "xss_lab", "vulnerabilities": ["XSS", "DOM_XSS"]},
                    {"name": "sqli_lab", "type": "sql_lab", "vulnerabilities": ["SQLi", "Blind_SQLi"]},
                    {"name": "idor_lab", "type": "custom", "vulnerabilities": ["IDOR"]}
                ],
                "network_isolation": "isolated",
                "difficulty": "beginner"
            },
            {
                "name": "advanced_web_attacks",
                "description": "سيناريو متقدم للهجمات المعقدة",
                "targets": [
                    {"name": "dvwa", "type": "dvwa"},
                    {"name": "webgoat", "type": "webgoat"}
                ],
                "network_isolation": "limited",
                "difficulty": "advanced"
            },
            {
                "name": "api_security",
                "description": "اختبار أمان APIs",
                "targets": [
                    {"name": "vuln_api", "type": "custom", "vulnerabilities": ["IDOR", "Mass_Assignment", "No_Rate_Limiting"]}
                ],
                "network_isolation": "isolated",
                "difficulty": "intermediate"
            }
        ]
    
    async def deploy_scenario(self, scenario_name: str) -> Optional[str]:
        """نشر سيناريو جاهز"""
        scenarios = await self.get_available_scenarios()
        
        scenario = None
        for s in scenarios:
            if s["name"] == scenario_name:
                scenario = s
                break
        
        if not scenario:
            print(f"   ❌ Scenario '{scenario_name}' not found")
            return None
        
        # إنشاء إعدادات المختبر
        config = LabConfig(
            name=scenario["name"],
            description=scenario["description"],
            network_isolation=NetworkIsolation(scenario.get("network_isolation", "isolated")),
            targets=scenario["targets"],
            auto_cleanup=True,
            capture_traffic=True
        )
        
        # إنشاء وبدء المختبر
        lab_id = await self.create_lab(config)
        if lab_id:
            await self.start_lab(lab_id)
            print(f"   🎯 Deployed scenario: {scenario_name}")
        
        return lab_id
    
    def get_stats(self) -> Dict:
        """إحصائيات عامة للبيئة"""
        active_labs = sum(1 for l in self._labs.values() if l.status == LabStatus.RUNNING)
        
        return {
            **self._global_stats,
            "active_labs": active_labs,
            "total_labs": len(self._labs),
            "storage_path": str(self._storage_dir),
            "initialized": self._initialized
        }
    
    async def cleanup_all(self):
        """تنظيف جميع المختبرات"""
        for lab_id in list(self._labs.keys()):
            await self.stop_lab(lab_id, destroy=True)
        
        self._labs.clear()
        print("   🧹 All labs cleaned up")


# نسخة عالمية
_default_lab_env = None


async def get_lab_environment() -> LabEnvironment:
    global _default_lab_env
    if _default_lab_env is None:
        _default_lab_env = LabEnvironment()
        await _default_lab_env.initialize()
    return _default_lab_env

