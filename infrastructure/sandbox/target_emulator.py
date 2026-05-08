
import asyncio
import docker
import random
import tempfile
import os
import yaml
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .docker_runtime import DockerRuntime, ContainerConfig, ContainerStatus, get_docker_runtime


class TargetType(Enum):
    """أنواع الأهداف"""
    DVWA = "dvwa"           # Damn Vulnerable Web Application
    BWAPP = "bwapp"         # Buggy Web Application
    WEBGOAT = "webgoat"     # WebGoat
    JUICESHOP = "juiceshop" # OWASP Juice Shop
    VULN_WEB = "vuln_web"   # تطبيق ويب ضعيف مخصص
    VULN_API = "vuln_api"   # API ضعيف
    SQL_LAB = "sql_lab"     # مختبر SQL Injection
    XSS_LAB = "xss_lab"     # مختبر XSS
    CUSTOM = "custom"       # هدف مخصص


class TargetStatus(Enum):
    """حالة الهدف"""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"
    PAUSED = "paused"


@dataclass
class TargetConfig:
    """إعدادات الهدف"""
    name: str
    target_type: TargetType
    image: str
    port_mappings: Dict[int, int]  # host_port -> container_port
    environment: Dict[str, str] = field(default_factory=dict)
    volumes: List[str] = field(default_factory=list)
    memory_limit: str = "512m"
    cpu_limit: float = 0.5
    health_check_path: str = "/"
    health_check_interval: int = 5
    startup_timeout: int = 30
    
    # بيانات تسجيل الدخول الافتراضية
    default_credentials: Dict[str, str] = field(default_factory=lambda: {
        "username": "admin",
        "password": "password"
    })
    
    # وصف الثغرات الموجودة
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class TargetInstance:
    """مثيل هدف قيد التشغيل"""
    config: TargetConfig
    container_id: str
    status: TargetStatus
    start_time: datetime
    url: str
    host_port: int
    metrics: Dict[str, Any] = field(default_factory=dict)


class TargetEmulator:
    """محاكي الأهداف - بيئة اختبار آمنة"""
    
    # الأهداف الجاهزة
    READY_TARGETS = {
        TargetType.DVWA: TargetConfig(
            name="DVWA",
            target_type=TargetType.DVWA,
            image="vulnerables/web-dvwa:latest",
            port_mappings={8080: 80},
            environment={},
            health_check_path="/login.php",
            default_credentials={"username": "admin", "password": "password"},
            vulnerabilities=["SQLi", "XSS", "CSRF", "File Inclusion", "Upload", "RCE"]
        ),
        
        TargetType.WEBGOAT: TargetConfig(
            name="WebGoat",
            target_type=TargetType.WEBGOAT,
            image="webgoat/goatandwolf:latest",
            port_mappings={8080: 8080},
            environment={},
            health_check_path="/WebGoat",
            default_credentials={"username": "guest", "password": "guest"},
            vulnerabilities=["SQLi", "XSS", "IDOR", "Path Traversal", "JWT", "SSRF"]
        ),
        
        TargetType.JUICESHOP: TargetConfig(
            name="Juice Shop",
            target_type=TargetType.JUICESHOP,
            image="bkimminich/juice-shop:latest",
            port_mappings={3000: 3000},
            environment={},
            health_check_path="/#/",
            default_credentials={"username": "admin@juice-sh.op", "password": "admin123"},
            vulnerabilities=["SQLi", "XSS", "IDOR", "Broken Auth", "Sensitive Data"]
        ),
        
        TargetType.BWAPP: TargetConfig(
            name="bWAPP",
            target_type=TargetType.BWAPP,
            image="raesene/bwapp",
            port_mappings={8080: 80},
            environment={"MYSQL_ROOT_PASSWORD": "bug"},
            health_check_path="/login.php",
            default_credentials={"username": "bee", "password": "bug"},
            vulnerabilities=["SQLi", "XSS", "LFI", "RCE", "XXE", "SSRF"]
        )
    }
    
    def __init__(self):
        self._runtime: Optional[DockerRuntime] = None
        self._targets: Dict[str, TargetInstance] = {}
        self._lock = asyncio.Lock()
        self._initialized = False
        self._used_ports: set = set()
        
        # إحصائيات الهجمات على الأهداف
        self._attack_stats: Dict[str, Dict] = {}
        
    async def initialize(self):
        """تهيئة المحاكي"""
        if self._initialized:
            return
        
        self._runtime = await get_docker_runtime()
        
        # التحقق من توفر Docker
        if not self._runtime.is_available():
            print("   ⚠️ Docker غير متوفر - سيتم استخدام المحاكاة المحلية")
        
        self._initialized = True
        print("   🎯 Target emulator initialized")
    
    def _get_available_port(self, preferred: int = None) -> int:
        """الحصول على منفذ متاح"""
        if preferred and preferred not in self._used_ports:
            self._used_ports.add(preferred)
            return preferred
        
        # البحث عن منفذ عشوائي متاح
        for port in range(18000, 19000):
            if port not in self._used_ports:
                self._used_ports.add(port)
                return port
        
        raise RuntimeError("No available ports")
    
    async def start_target(
        self,
        target_type: TargetType,
        custom_config: Optional[TargetConfig] = None,
        name: str = None
    ) -> Optional[TargetInstance]:
        """
        بدء تشغيل هدف
        
        Args:
            target_type: نوع الهدف
            custom_config: إعدادات مخصصة (لـ CUSTOM)
            name: اسم مخصص للهدف
        
        Returns:
            TargetInstance أو None في حال الفشل
        """
        async with self._lock:
            # الحصول على الإعدادات
            if target_type == TargetType.CUSTOM:
                if not custom_config:
                    raise ValueError("Custom target requires custom_config")
                config = custom_config
            else:
                config = self.READY_TARGETS.get(target_type)
                if not config:
                    raise ValueError(f"Unknown target type: {target_type}")
            
            # تخصيص الاسم
            instance_name = name or f"{config.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            if instance_name in self._targets:
                print(f"   ⚠️ Target {instance_name} already exists")
                return self._targets[instance_name]
            
            # تخصيص المنفذ المضيف
            host_port = self._get_available_port(list(config.port_mappings.keys())[0])
            container_port = list(config.port_mappings.values())[0]
            
            # إعداد متغيرات البيئة
            environment = config.environment.copy()
            environment.update({
                "TARGET_NAME": instance_name,
                "TARGET_TYPE": config.target_type.value
            })
            
            # إعداد volume mappings
            volumes = config.volumes.copy()
            
            print(f"   🚀 Starting target: {instance_name} ({config.target_type.value})")
            print(f"      Port: {host_port} -> {container_port}")
            
            # إنشاء إعدادات الحاوية
            container_config = ContainerConfig(
                image=config.image,
                command=[],
                environment=environment,
                volumes=volumes,
                working_dir="/",
                memory_limit=config.memory_limit,
                cpu_limit=config.cpu_limit,
                port_mappings={host_port: container_port},
                read_only=False,  # الأهداف تحتاج إلى كتابة
                security_opt=[],
                tmpfs={}
            )
            
            try:
                # إنشاء الحاوية
                container = await self._runtime.create_container(
                    name=f"target_{instance_name.lower().replace(' ', '_')}",
                    config=container_config
                )
                
                if not container:
                    print(f"   ❌ Failed to create container for {instance_name}")
                    return None
                
                # بدء الحاوية
                if not await self._runtime.start_container(container.id):
                    print(f"   ❌ Failed to start container for {instance_name}")
                    await self._runtime.remove_container(container.id)
                    return None
                
                # انتظار الهدف ليصبح جاهزاً
                url = f"http://localhost:{host_port}{config.health_check_path}"
                ready = await self._wait_for_target_ready(url, config.startup_timeout)
                
                if not ready:
                    print(f"   ⚠️ Target {instance_name} started but health check failed")
                
                # إنشاء مثيل الهدف
                instance = TargetInstance(
                    config=config,
                    container_id=container.id,
                    status=TargetStatus.RUNNING,
                    start_time=datetime.now(),
                    url=f"http://localhost:{host_port}",
                    host_port=host_port,
                    metrics={
                        "requests_served": 0,
                        "attacks_detected": 0,
                        "last_access": None,
                        "total_response_time": 0.0
                    }
                )
                
                self._targets[instance_name] = instance
                self._attack_stats[instance_name] = {
                    "total_attacks": 0,
                    "successful_attacks": 0,
                    "failed_attacks": 0,
                    "attack_types": {},
                    "vulnerabilities_found": []
                }
                
                print(f"   ✅ Target {instance_name} is running at {instance.url}")
                print(f"      Default credentials: {config.default_credentials}")
                
                return instance
                
            except Exception as e:
                print(f"   ❌ Failed to start target {instance_name}: {e}")
                return None
    
    async def _wait_for_target_ready(
        self,
        url: str,
        timeout: int = 30,
        interval: int = 2
    ) -> bool:
        """انتظار الهدف ليصبح جاهزاً"""
        import aiohttp
        
        start_time = datetime.now()
        
        while (datetime.now() - start_time).total_seconds() < timeout:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=5) as response:
                        if response.status < 500:
                            return True
            except:
                pass
            
            await asyncio.sleep(interval)
        
        return False
    
    async def stop_target(self, name: str, remove: bool = True) -> bool:
        """إيقاف هدف"""
        async with self._lock:
            if name not in self._targets:
                print(f"   ⚠️ Target {name} not found")
                return False
            
            instance = self._targets[name]
            instance.status = TargetStatus.STOPPING
            
            # إيقاف الحاوية
            if await self._runtime.stop_container(instance.container_id):
                instance.status = TargetStatus.STOPPED
                print(f"   🛑 Target {name} stopped")
                
                if remove:
                    await self._runtime.remove_container(instance.container_id)
                    # تحرير المنفذ
                    self._used_ports.discard(instance.host_port)
                    del self._targets[name]
                    print(f"   🗑️ Target {name} removed")
                
                return True
            
            instance.status = TargetStatus.ERROR
            return False
    
    async def stop_all_targets(self) -> int:
        """إيقاف جميع الأهداف"""
        tasks = []
        for name in list(self._targets.keys()):
            tasks.append(self.stop_target(name, remove=True))
        
        results = await asyncio.gather(*tasks)
        return sum(results)
    
    async def get_target_status(self, name: str = None) -> Dict:
        """الحصول على حالة الهدف/الأهداف"""
        if name:
            if name not in self._targets:
                return {"error": f"Target {name} not found"}
            instance = self._targets[name]
            return {
                "name": name,
                "type": instance.config.target_type.value,
                "status": instance.status.value,
                "url": instance.url,
                "uptime": (datetime.now() - instance.start_time).total_seconds(),
                "metrics": instance.metrics,
                "attack_stats": self._attack_stats.get(name, {})
            }
        
        # جميع الأهداف
        return {
            name: {
                "type": inst.config.target_type.value,
                "status": inst.status.value,
                "url": inst.url,
                "uptime": (datetime.now() - inst.start_time).total_seconds()
            }
            for name, inst in self._targets.items()
        }
    
    async def record_attack(
        self,
        target_name: str,
        attack_type: str,
        success: bool,
        payload: str = None,
        details: Dict = None
    ):
        """تسجيل هجوم على هدف"""
        if target_name not in self._attack_stats:
            return
        
        stats = self._attack_stats[target_name]
        stats["total_attacks"] += 1
        
        if success:
            stats["successful_attacks"] += 1
            if attack_type and attack_type not in stats["attack_types"]:
                stats["attack_types"][attack_type] = 0
            stats["attack_types"][attack_type] = stats["attack_types"].get(attack_type, 0) + 1
        
        else:
            stats["failed_attacks"] += 1
        
        # تحديث مثيل الهدف
        if target_name in self._targets:
            instance = self._targets[target_name]
            instance.metrics["attacks_detected"] += 1
            instance.metrics["last_access"] = datetime.now().isoformat()
    
    async def mark_vulnerability_found(self, target_name: str, vulnerability: str):
        """تسجيل ثغرة مكتشفة"""
        if target_name in self._attack_stats:
            vulns = self._attack_stats[target_name]["vulnerabilities_found"]
            if vulnerability not in vulns:
                vulns.append(vulnerability)
    
    async def create_custom_vulnerable_app(
        self,
        name: str,
        vulnerabilities: List[str],
        port: int = None
    ) -> Optional[TargetInstance]:
        """
        إنشاء تطبيق ويب ضعيف مخصص باستخدام Nginx + PHP
        """
        # إنشاء ملفات التطبيق المؤقتة
        with tempfile.TemporaryDirectory() as temp_dir:
            # إنشاء ملف index.php مع الثغرات
            index_content = self._generate_vulnerable_php(vulnerabilities)
            
            index_path = os.path.join(temp_dir, "index.php")
            with open(index_path, "w") as f:
                f.write(index_content)
            
            # إنشاء Dockerfile
            dockerfile_content = '''
            FROM php:8.1-apache
            RUN docker-php-ext-install mysqli pdo pdo_mysql
            COPY index.php /var/www/html/
            RUN chmod 755 /var/www/html/index.php
            EXPOSE 80
            '''
            
            dockerfile_path = os.path.join(temp_dir, "Dockerfile")
            with open(dockerfile_path, "w") as f:
                f.write(dockerfile_content)
            
            # بناء الصورة
            image_name = f"custom_vuln_{name.lower()}"
            
            print(f"   🏗️ Building custom image: {image_name}")
            
            # استخدام Docker SDK لبناء الصورة
            try:
                client = docker.from_env()
                image, logs = client.images.build(
                    path=temp_dir,
                    tag=image_name,
                    rm=True
                )
                print(f"   ✅ Built image: {image_name}")
                
                # إنشاء إعدادات الهدف المخصص
                custom_config = TargetConfig(
                    name=name,
                    target_type=TargetType.CUSTOM,
                    image=image_name,
                    port_mappings={port or 8000: 80},
                    environment={},
                    vulnerabilities=vulnerabilities,
                    default_credentials={"username": "admin", "password": "password"}
                )
                
                # بدء الهدف
                return await self.start_target(
                    TargetType.CUSTOM,
                    custom_config=custom_config,
                    name=name
                )
                
            except Exception as e:
                print(f"   ❌ Failed to build custom image: {e}")
                return None
    
    def _generate_vulnerable_php(self, vulnerabilities: List[str]) -> str:
        """توليد كود PHP ضعيف حسب الثغرات المطلوبة"""
        php_code = """<?php
// Custom Vulnerable Web Application
// This is a SAFE testing environment - DO NOT deploy in production!

session_start();
$message = "";
$result = "";

// Database simulation
$users = [
    "admin" => "password123",
    "user" => "userpass",
    "test" => "test123"
];

$data = [
    "users" => [
        ["id"=>1, "name"=>"Admin", "email"=>"admin@example.com", "role"=>"admin"],
        ["id"=>2, "name"=>"John", "email"=>"john@example.com", "role"=>"user"],
        ["id"=>3, "name"=>"Jane", "email"=>"jane@example.com", "role"=>"user"]
    ],
    "products" => [
        ["id"=>1, "name"=>"Product 1", "price"=>100],
        ["id"=>2, "name"=>"Product 2", "price"=>200],
        ["id"=>3, "name"=>"Product 3", "price"=>300]
    ]
];

// Helper function to simulate DB query
function query($sql) {
    global $data;
    if (strpos($sql, "users") !== false) {
        return ["success"=>true, "data"=>$data["users"]];
    }
    return ["success"=>false, "error"=>"Invalid query"];
}
"""
        
        # إضافة ثغرات محددة
        if "SQLi" in vulnerabilities or "SQL Injection" in vulnerabilities:
            php_code += """
// ===== SQL INJECTION VULNERABILITY =====
if(isset($_GET['user_id'])) {
    $id = $_GET['user_id'];
    // VULNERABLE: Direct concatenation of user input
    $sql = "SELECT * FROM users WHERE id = " . $id;
    $result = query($sql);
    if($result['success']) {
        echo "<h3>User Found:</h3><pre>";
        print_r($result['data']);
        echo "</pre>";
    }
}
"""
        
        if "XSS" in vulnerabilities:
            php_code += """
// ===== XSS VULNERABILITY =====
if(isset($_GET['search'])) {
    $search = $_GET['search'];
    // VULNERABLE: Output without escaping
    echo "<div class='search-result'>Search results for: " . $search . "</div>";
}

if(isset($_GET['name'])) {
    $name = $_GET['name'];
    // VULNERABLE: Reflected XSS
    echo "<h1>Welcome, " . $name . "</h1>";
}
"""
        
        if "IDOR" in vulnerabilities:
            php_code += """
// ===== IDOR VULNERABILITY =====
if(isset($_GET['profile_id'])) {
    $profile_id = $_GET['profile_id'];
    // VULNERABLE: No access control check
    echo "<div>Profile Data for ID: " . htmlspecialchars($profile_id) . "</div>";
    // Simulate returning any profile
    $profiles = [1=>"Admin Profile", 2=>"User Profile", 3=>"Secret Profile"];
    if(isset($profiles[$profile_id])) {
        echo "<pre>" . $profiles[$profile_id] . "</pre>";
    }
}
"""
        
        if "RCE" in vulnerabilities or "Command Injection" in vulnerabilities:
            php_code += """
// ===== COMMAND INJECTION / RCE =====
if(isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    // VULNERABLE: Direct command execution
    echo "<pre>";
    system($cmd);
    echo "</pre>";
}

if(isset($_GET['ping'])) {
    $host = $_GET['ping'];
    // VULNERABLE: Command injection in ping
    echo "<pre>";
    passthru("ping -c 4 " . $host);
    echo "</pre>";
}
"""
        
        if "File Inclusion" in vulnerabilities or "LFI" in vulnerabilities:
            php_code += """
// ===== FILE INCLUSION / LFI =====
if(isset($_GET['page'])) {
    $page = $_GET['page'];
    // VULNERABLE: Direct file inclusion
    include($page . ".php");
}

if(isset($_GET['file'])) {
    $file = $_GET['file'];
    // VULNERABLE: Path traversal
    echo file_get_contents($file);
}
"""
        
        # إضافة واجهة HTML
        php_code += """
?>
<!DOCTYPE html>
<html>
<head>
    <title>Custom Vulnerable Application</title>
    <style>
        body { font-family: monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
        .container { max-width: 1200px; margin: auto; }
        .vuln-box { border: 1px solid #ff4444; padding: 15px; margin: 10px 0; background: #2d2d2d; }
        .vuln-title { color: #ff4444; font-weight: bold; }
        input, select { padding: 5px; margin: 5px; background: #3c3c3c; border: 1px solid #555; color: #fff; }
        button { padding: 5px 15px; background: #007acc; color: white; border: none; cursor: pointer; }
        pre { background: #0d0d0d; padding: 10px; overflow-x: auto; }
        .nav { display: flex; gap: 20px; margin-bottom: 20px; }
        .nav a { color: #007acc; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔥 Custom Vulnerable Web Application</h1>
        <div class="nav">
            <a href="?">Home</a>
            <a href="?user_id=1">SQLi Test</a>
            <a href="?search=<script>alert('XSS')</script>">XSS Test</a>
            <a href="?profile_id=3">IDOR Test</a>
            <a href="?cmd=id">RCE Test</a>
            <a href="?page=../../../../etc/passwd">LFI Test</a>
        </div>
        
        <div class="vuln-box">
            <div class="vuln-title">⚠️ VULNERABILITIES PRESENT</div>
            <ul>
"""
        
        for vuln in vulnerabilities:
            php_code += f"                <li>{vuln}</li>\n"
        
        php_code += """
            </ul>
        </div>
        
        <div class="vuln-box">
            <div class="vuln-title">🎯 Test Forms</div>
            
            <h3>SQL Injection Test</h3>
            <form method="GET">
                <input type="text" name="user_id" placeholder="User ID (e.g., 1 OR 1=1)">
                <button type="submit">Query</button>
            </form>
            
            <h3>XSS Test</h3>
            <form method="GET">
                <input type="text" name="search" placeholder="Search term">
                <input type="text" name="name" placeholder="Your name">
                <button type="submit">Submit</button>
            </form>
            
            <h3>IDOR Test</h3>
            <form method="GET">
                <input type="number" name="profile_id" placeholder="Profile ID">
                <button type="submit">View Profile</button>
            </form>
            
            <h3>Command Injection Test</h3>
            <form method="GET">
                <input type="text" name="cmd" placeholder="Command (e.g., id, ls, whoami)">
                <input type="text" name="ping" placeholder="Host to ping">
                <button type="submit">Execute</button>
            </form>
            
            <h3>File Inclusion Test</h3>
            <form method="GET">
                <input type="text" name="page" placeholder="Page name">
                <input type="text" name="file" placeholder="File path">
                <button type="submit">Include</button>
            </form>
        </div>
        
        <div>
            <h3>📊 Results</h3>
            <?php
            if(isset($result) && $result) {
                echo "<pre>" . print_r($result, true) . "</pre>";
            }
            ?>
        </div>
        
        <div class="vuln-box" style="border-color: #44ff44;">
            <div class="vuln-title" style="color: #44ff44;">ℹ️ Information</div>
            <p>This is a SAFE testing environment. Vulnerabilities included: <?php echo implode(", ", " . json_encode(vulnerabilities) . "); ?></p>
            <p><strong>Default Credentials:</strong> admin/password123</p>
        </div>
    </div>
</body>
</html>
"""
        
        return php_code
    
    async def scan_available_targets(self) -> List[Dict]:
        """فحص الأهداف المتوفرة في Docker Hub"""
        available = []
        
        for target_type, config in self.READY_TARGETS.items():
            available.append({
                "name": config.name,
                "type": target_type.value,
                "image": config.image,
                "vulnerabilities": config.vulnerabilities,
                "default_credentials": config.default_credentials
            })
        
        return available
    
    def get_stats(self) -> Dict:
        """إحصائيات المحاكي"""
        return {
            "total_targets": len(self._targets),
            "running_targets": sum(1 for t in self._targets.values() if t.status == TargetStatus.RUNNING),
            "total_attacks": sum(s["total_attacks"] for s in self._attack_stats.values()),
            "successful_attacks": sum(s["successful_attacks"] for s in self._attack_stats.values()),
            "vulnerabilities_found": sum(len(s["vulnerabilities_found"]) for s in self._attack_stats.values()),
            "used_ports": list(self._used_ports),
            "initialized": self._initialized
        }


# نسخة عالمية
_default_emulator = None


async def get_target_emulator() -> TargetEmulator:
    global _default_emulator
    if _default_emulator is None:
        _default_emulator = TargetEmulator()
        await _default_emulator.initialize()
    return _default_emulator

