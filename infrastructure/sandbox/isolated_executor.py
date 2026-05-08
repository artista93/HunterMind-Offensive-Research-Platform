
import asyncio
import tempfile
import os
from collections import deque
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from .docker_runtime import DockerRuntime, ContainerConfig, ContainerStatus, get_docker_runtime


class ExecutionResult(Enum):
    """نتائج التنفيذ"""
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"
    SANDBOX_ERROR = "sandbox_error"


@dataclass
class ExecutedCommand:
    """أمر تم تنفيذه"""
    command: str
    args: List[str]
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    result: ExecutionResult
    timestamp: datetime = field(default_factory=datetime.now)


class IsolatedExecutor:
    """منفذ أوامر معزول باستخدام Docker"""
    
    def __init__(self, max_history: int = 100):
        self._runtime: Optional[DockerRuntime] = None
        self._execution_history: deque = deque(maxlen=max_history)  # ✅ ring buffer
        self._active_containers: Dict[str, str] = {}
        self._lock = asyncio.Lock()
        self._initialized = False
        
        # إحصائيات
        self._stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "timeout_executions": 0
        }
    
    async def initialize(self):
        """تهيئة المنفذ"""
        if self._initialized:
            return
        
        self._runtime = await get_docker_runtime()
        self._initialized = True
        print("   🛡️ Isolated executor initialized")
    
    async def _execute_in_container(
        self,
        image: str,
        command: List[str],
        working_dir: str = "/work",
        timeout: int = 60,
        memory_limit: str = "256m",
        cpu_limit: float = 0.5,
        environment: Dict[str, str] = None,
        volumes: List[str] = None
    ) -> Tuple[ExecutionResult, str, str, float]:
        """
        التنفيذ الأساسي في حاوية (مستخدم داخلياً)
        """
        if not self._initialized:
            await self.initialize()
        
        if not self._runtime.is_available():
            return ExecutionResult.SANDBOX_ERROR, "", "Docker not available", 0.0
        
        start_time = datetime.now()
        
        try:
            # إعداد الحاوية
            config = ContainerConfig(
                image=image,
                command=command,
                environment=environment or {},
                volumes=volumes or [],
                working_dir=working_dir,
                memory_limit=memory_limit,
                cpu_limit=cpu_limit,
                read_only=True,
                security_opt=["no-new-privileges:true"],
                tmpfs={"/tmp": ""},
                timeout=timeout
            )
            
            # إنشاء الحاوية
            container = await self._runtime.create_container(
                name=f"exec_{command[0][:20]}_{int(start_time.timestamp())}",
                config=config
            )
            
            if not container:
                return ExecutionResult.SANDBOX_ERROR, "", "Failed to create container", 0.0
            
            # بدء الحاوية
            started = await self._runtime.start_container(container.id)
            if not started:
                await self._runtime.remove_container(container.id)
                return ExecutionResult.SANDBOX_ERROR, "", "Failed to start container", 0.0
            
            # انتظار انتهاء التنفيذ (✅ استخدام ContainerStatus)
            exec_start = datetime.now()
            exit_code = None
            stdout = ""
            stderr = ""
            
            while (datetime.now() - exec_start).total_seconds() < timeout:
                status = await self._runtime.get_container_status(container.id)
                if status == ContainerStatus.STOPPED:
                    logs = await self._runtime.get_container_logs(container.id)
                    stdout = "\n".join(logs)
                    exit_code = 0
                    break
                await asyncio.sleep(0.5)
            
            # تنظيف الحاوية
            await self._runtime.stop_container(container.id)
            await self._runtime.remove_container(container.id)
            
            execution_time = (datetime.now() - start_time).total_seconds()
            result = ExecutionResult.SUCCESS if exit_code == 0 else ExecutionResult.FAILED
            
            if (datetime.now() - exec_start).total_seconds() >= timeout:
                result = ExecutionResult.TIMEOUT
                self._stats["timeout_executions"] += 1
            
            return result, stdout, stderr, execution_time
            
        except Exception as e:
            return ExecutionResult.SANDBOX_ERROR, "", str(e), 0.0
    
    async def execute_command(
        self,
        command: str,
        args: List[str] = None,
        working_dir: str = "/work",
        timeout: int = 60,
        memory_limit: str = "256m",
        cpu_limit: float = 0.5,
        image: str = "alpine:latest",
        environment: Dict[str, str] = None,
        input_data: str = None
    ) -> Tuple[ExecutionResult, str, str, float]:
        """
        تنفيذ أمر بشكل معزول
        """
        full_command = [command] + (args or [])
        
        result, stdout, stderr, exec_time = await self._execute_in_container(
            image=image,
            command=full_command,
            working_dir=working_dir,
            timeout=timeout,
            memory_limit=memory_limit,
            cpu_limit=cpu_limit,
            environment=environment
        )
        
        # تسجيل الإحصائيات والتاريخ
        self._stats["total_executions"] += 1
        if result == ExecutionResult.SUCCESS:
            self._stats["successful_executions"] += 1
        else:
            self._stats["failed_executions"] += 1
        
        self._execution_history.append(ExecutedCommand(
            command=command,
            args=args or [],
            stdout=stdout[:1000],
            stderr=stderr[:500],
            exit_code=0 if result == ExecutionResult.SUCCESS else -1,
            execution_time=exec_time,
            result=result
        ))
        
        return result, stdout, stderr, exec_time
    
    async def execute_python(
        self,
        code: str,
        timeout: int = 30,
        memory_limit: str = "128m",
        packages: List[str] = None
    ) -> Tuple[ExecutionResult, str, str, float]:
        """
        تنفيذ كود Python في بيئة معزولة باستخدام ملف مؤقت
        """
        # ✅ إنشاء ملف مؤقت للكود (يحل مشكلة multi-line)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            script_path = f.name
        
        # تحضير الأوامر
        command = ["python", script_path]
        
        # تثبيت حزم إضافية إذا لزم الأمر
        if packages:
            install_cmd = f"pip install {' '.join(packages)} && "
            # نستخدم شل لتنفيذ التثبيت ثم التشغيل
            full_script = f"{install_cmd} python {script_path}"
            return await self.execute_shell(full_script, timeout=timeout + 10, memory_limit=memory_limit)
        
        try:
            result, stdout, stderr, exec_time = await self._execute_in_container(
                image="python:3.11-slim",
                command=command,
                timeout=timeout,
                memory_limit=memory_limit,
                environment={"PYTHONUNBUFFERED": "1"}
            )
            
            # تسجيل الإحصائيات
            self._stats["total_executions"] += 1
            if result == ExecutionResult.SUCCESS:
                self._stats["successful_executions"] += 1
            else:
                self._stats["failed_executions"] += 1
            
            return result, stdout, stderr, exec_time
            
        finally:
            # تنظيف الملف المؤقت
            try:
                os.unlink(script_path)
            except:
                pass
    
    async def execute_shell(
        self,
        script: str,
        timeout: int = 30,
        memory_limit: str = "128m"
    ) -> Tuple[ExecutionResult, str, str, float]:
        """تنفيذ سكربت Shell في بيئة معزولة"""
        
        # ✅ إنشاء ملف مؤقت للسكربت
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(f"#!/bin/sh\n{script}")
            script_path = f.name
            os.chmod(script_path, 0o755)
        
        try:
            command = ["sh", script_path]
            
            result, stdout, stderr, exec_time = await self._execute_in_container(
                image="alpine:latest",
                command=command,
                timeout=timeout,
                memory_limit=memory_limit
            )
            
            return result, stdout, stderr, exec_time
            
        finally:
            try:
                os.unlink(script_path)
            except:
                pass
    
    async def execute_binary(
        self,
        binary_path: str,
        args: List[str] = None,
        input_data: str = None,
        timeout: int = 30,
        memory_limit: str = "256m"
    ) -> Tuple[ExecutionResult, str, str, float]:
        """
        تنفيذ ملف ثنائي في بيئة معزولة
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            import shutil
            binary_name = os.path.basename(binary_path)
            dest_path = os.path.join(temp_dir, binary_name)
            shutil.copy(binary_path, dest_path)
            os.chmod(dest_path, 0o755)
            
            return await self.execute_command(
                command=f"./{binary_name}",
                args=args,
                working_dir=temp_dir,
                timeout=timeout,
                memory_limit=memory_limit,
                image="alpine:latest"
            )
    
    async def test_url_safely(
        self,
        url: str,
        timeout: int = 10
    ) -> Tuple[bool, str, int]:
        """
        اختبار URL بشكل آمن
        """
        script = f"""
        curl -s -o /dev/null -w "%{{http_code}}" --max-time {timeout} "{url}"
        """
        
        result, stdout, stderr, _ = await self.execute_shell(script, timeout=timeout+5)
        
        if result == ExecutionResult.SUCCESS and stdout.strip().isdigit():
            return True, stdout.strip(), int(stdout.strip())
        
        return False, stderr, 0
    
    async def download_file_safely(
        self,
        url: str,
        timeout: int = 30
    ) -> Tuple[bool, str]:
        """
        تحميل ملف بشكل آمن
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            script = f"""
            cd {temp_dir}
            curl -s -O "{url}"
            ls -la
            """
            
            result, stdout, stderr, _ = await self.execute_shell(script, timeout=timeout)
            
            if result == ExecutionResult.SUCCESS:
                files = [f for f in os.listdir(temp_dir) if os.path.isfile(os.path.join(temp_dir, f))]
                if files:
                    safe_path = os.path.join("/tmp", files[0])
                    import shutil
                    shutil.copy(os.path.join(temp_dir, files[0]), safe_path)
                    return True, safe_path
            
            return False, ""
    
    async def scan_file_safely(
        self,
        file_path: str,
        timeout: int = 60
    ) -> Tuple[bool, str]:
        """
        فحص ملف للبحث عن أنماط ضارة (محسن)
        """
        # فحص متعدد المستويات
        script = f"""
        # المستوى 1: فحص الأنماط الأساسية
        echo "=== Pattern Scan ==="
        strings "{file_path}" | grep -E -i "(eval|exec|system|shell_exec|base64_decode|<?php|<script|powershell|cmd.exe|wscript|cscript)" | head -20
        
        # المستوى 2: فحص التشفير
        echo "=== Entropy Check ==="
        strings "{file_path}" | while read line; do
            if [ $(echo "$line" | wc -c) -gt 50 ]; then
                echo "Long string detected: $line"
            fi
        done | head -10
        
        # المستوى 3: فحص الملفات القابلة للتنفيذ
        echo "=== Executable Check ==="
        file "{file_path}" | grep -E "(executable|script)"
        """
        
        result, stdout, stderr, _ = await self.execute_shell(script, timeout=timeout)
        
        if result == ExecutionResult.SUCCESS:
            suspicious = len(stdout.strip()) > 0
            return suspicious, stdout
        
        return False, ""
    
    def get_stats(self) -> Dict:
        """إحصائيات المنفذ"""
        return {
            **self._stats,
            "success_rate": self._stats["successful_executions"] / max(1, self._stats["total_executions"]),
            "history_size": len(self._execution_history),
            "initialized": self._initialized,
            "docker_available": self._runtime.is_available() if self._runtime else False
        }
    
    def get_recent_executions(self, limit: int = 10) -> List[Dict]:
        """آخر عمليات التنفيذ"""
        recent = list(self._execution_history)[-limit:]
        return [
            {
                "command": e.command,
                "args": e.args,
                "exit_code": e.exit_code,
                "execution_time": e.execution_time,
                "result": e.result.value,
                "timestamp": e.timestamp.isoformat()
            }
            for e in recent
        ]
    
    async def cleanup(self):
        """تنظيف الموارد"""
        self._initialized = False


# نسخة عالمية
_default_executor = None


async def get_isolated_executor() -> IsolatedExecutor:
    global _default_executor
    if _default_executor is None:
        _default_executor = IsolatedExecutor()
        await _default_executor.initialize()
    return _default_executor

