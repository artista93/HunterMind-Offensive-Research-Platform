
import random
import json
import asyncio
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

from .payload_generator import Payload, PayloadType, get_payload_generator
from .payload_mutator import get_payload_mutator
from .payload_encoder import get_payload_encoder
from .payload_ranker import get_payload_ranker
from .payload_library import get_payload_library
from .context_payload_builder import get_context_payload_builder, ContextAnalysis

import logging

logger = logging.getLogger(__name__)


@dataclass
class EvolutionIndividual:
    """فرد في التطور"""
    payload: Payload
    fitness: float  # درجة اللياقة (0-100)
    generation: int
    parent_ids: List[str] = field(default_factory=list)
    mutation_count: int = 0
    success_count: int = 0
    fail_count: int = 0


@dataclass
class EvolutionStats:
    """إحصائيات التطور"""
    generation: int
    population_size: int
    best_fitness: float
    avg_fitness: float
    total_mutations: int
    successful_individuals: int
    timestamp: datetime


class PayloadEvolver:
    """
    تطور الحمولات المتقدم
    
    الميزات:
    - خوارزميات وراثية لتطور الحمولات
    - اختيار الأفضل (Selection)
    - تقاطع بين حمولات (Crossover)
    - تحوير عشوائي (Mutation)
    - تقييم اللياقة (Fitness)
    - تطور تكيفي حسب النجاحات
    - توليد أجيال جديدة من الحمولات
    - دعم multi-objective optimization
    """
    
    # معاملات الخوارزمية الجينية
    DEFAULT_PARAMS = {
        "population_size": 50,
        "elite_size": 5,      # عدد الأفراد المتميزين الذين ينتقلون مباشرة
        "crossover_rate": 0.7,
        "mutation_rate": 0.2,
        "max_generations": 100,
        "target_fitness": 95.0,
        "tournament_size": 3,
    }
    
    def __init__(self):
        self._generator = get_payload_generator()
        self._mutator = get_payload_mutator()
        self._encoder = get_payload_encoder()
        self._ranker = get_payload_ranker()
        self._library = None  # سيتم تهيئته لاحقاً
        self._context_builder = get_context_payload_builder()
        
        self._population: List[EvolutionIndividual] = []
        self._generation = 0
        self._stats_history: List[EvolutionStats] = []
        self._params = self.DEFAULT_PARAMS.copy()
        self._running = False
        self._best_individual = None
        
        logger.info("PayloadEvolver initialized")
    
    async def initialize_library(self):
        """تهيئة مكتبة الحمولات"""
        self._library = await get_payload_library()
    
    async def create_initial_population(
        self,
        payload_type: PayloadType = PayloadType.XSS,
        size: int = None
    ) -> List[EvolutionIndividual]:
        """
        إنشاء الجيل الأول من الحمولات
        
        Args:
            payload_type: نوع الحمولة
            size: حجم السكان (استخدام الافتراضي إذا لم يحدد)
        
        Returns:
            قائمة بالأفراد
        """
        if size is None:
            size = self._params["population_size"]
        
        population = []
        
        # توليد حمولات أساسية
        if payload_type == PayloadType.XSS:
            base_payloads = self._generator.generate_xss_payloads(max_payloads=size // 2)
        elif payload_type == PayloadType.SQLI:
            base_payloads = self._generator.generate_sqli_payloads(max_payloads=size // 2)
        elif payload_type == PayloadType.RCE:
            base_payloads = self._generator.generate_rce_payloads(max_payloads=size // 2)
        else:
            base_payloads = self._generator.generate_random_payloads(payload_type, count=size // 2)
        
        # إضافة حمولات متحورة
        mutated_payloads = self._mutator.mutate_batch(base_payloads, mutations_per_payload=1)
        
        # إضافة حمولات من المكتبة
        if self._library:
            library_payloads = await self._library.search_payloads(
                payload_type=payload_type,
                limit=size // 4
            )
        else:
            library_payloads = []
        
        # إنشاء الأفراد
        for i, payload in enumerate(base_payloads[:size//2]):
            individual = EvolutionIndividual(
                payload=payload,
                fitness=await self._calculate_fitness(payload),
                generation=0,
                parent_ids=[],
                mutation_count=0
            )
            population.append(individual)
        
        for result in mutated_payloads[:size//4]:
            individual = EvolutionIndividual(
                payload=result.mutated,
                fitness=await self._calculate_fitness(result.mutated),
                generation=0,
                parent_ids=[],
                mutation_count=1
            )
            population.append(individual)
        
        for entry in library_payloads[:size//4]:
            # تحويل PayloadEntry إلى Payload
            payload = Payload(
                id=entry.id,
                name=entry.name,
                type=entry.type,
                payload=entry.payload,
                encoding=entry.encoding,
                description=f"From library: {entry.name}",
                tags=entry.tags
            )
            individual = EvolutionIndividual(
                payload=payload,
                fitness=entry.rating,
                generation=0,
                parent_ids=[]
            )
            population.append(individual)
        
        # ملء الباقي بحمولات عشوائية
        while len(population) < size:
            random_payloads = self._generator.generate_random_payloads(payload_type, count=1)
            if random_payloads:
                individual = EvolutionIndividual(
                    payload=random_payloads[0],
                    fitness=random.uniform(0, 30),
                    generation=0
                )
                population.append(individual)
        
        self._population = population
        self._generation = 0
        
        logger.info(f"Created initial population of {len(population)} individuals")
        return population
    
    async def _calculate_fitness(self, payload: Payload) -> float:
        """
        حساب درجة اللياقة للحمولة
        
        المعايير:
        - درجة التقييم من الرانكر
        - معاملات إضافية: الطول، التعقيد، الجدة
        """
        # الحصول على درجة الرانكر
        ranker_scores = self._ranker.rank_payloads([payload])
        ranker_score = ranker_scores[0].total_score if ranker_scores else 5.0
        
        # معامل الطول (الحمولات القصيرة أفضل)
        length_score = max(0, 10 - len(payload.payload) / 50)
        length_score = min(length_score, 10)
        
        # معامل الجدة
        novelty_score = 5.0
        if "mutated" in payload.tags:
            novelty_score += 2.0
        if "polymorphic" in payload.tags:
            novelty_score += 3.0
        if "random" in payload.tags:
            novelty_score += 4.0
        
        # درجة اللياقة النهائية
        fitness = (ranker_score * 0.6) + (length_score * 0.2) + (novelty_score * 0.2)
        
        return min(fitness, 100.0)
    
    async def evolve_generation(self) -> List[EvolutionIndividual]:
        """
        تطور جيل جديد من الحمولات
        
        المراحل:
        1. اختيار الأفضل (Selection)
        2. تقاطع (Crossover)
        3. تحوير (Mutation)
        4. تقييم اللياقة (Fitness)
        """
        if len(self._population) < 2:
            return self._population
        
        new_population = []
        
        # 1. الحفاظ على النخبة (Elite)
        elite = sorted(self._population, key=lambda x: x.fitness, reverse=True)[:self._params["elite_size"]]
        new_population.extend(elite)
        
        # 2. إنشاء الجيل الجديد
        while len(new_population) < self._params["population_size"]:
            # اختيار الوالدين
            parent1 = self._tournament_selection()
            parent2 = self._tournament_selection()
            
            # تقاطع
            if random.random() < self._params["crossover_rate"]:
                child_payload = await self._crossover(parent1.payload, parent2.payload)
            else:
                child_payload = parent1.payload
            
            # تحوير
            if random.random() < self._params["mutation_rate"]:
                child_payload = await self._mutate(child_payload)
                mutation_count = 1
            else:
                mutation_count = 0
            
            # إنشاء الفرد الجديد
            individual = EvolutionIndividual(
                payload=child_payload,
                fitness=await self._calculate_fitness(child_payload),
                generation=self._generation + 1,
                parent_ids=[parent1.payload.id, parent2.payload.id],
                mutation_count=mutation_count
            )
            
            new_population.append(individual)
        
        # تحديث السكان
        self._population = new_population
        self._generation += 1
        
        # تحديث الإحصائيات
        await self._update_stats()
        
        # تحديث أفضل فرد
        current_best = max(self._population, key=lambda x: x.fitness)
        if not self._best_individual or current_best.fitness > self._best_individual.fitness:
            self._best_individual = current_best
        
        logger.info(f"Generation {self._generation}: best fitness = {current_best.fitness:.2f}, avg = {self._stats_history[-1].avg_fitness:.2f}")
        
        return self._population
    
    def _tournament_selection(self) -> EvolutionIndividual:
        """اختيار بواسطة البطولة (Tournament Selection)"""
        tournament_size = self._params["tournament_size"]
        participants = random.sample(self._population, min(tournament_size, len(self._population)))
        return max(participants, key=lambda x: x.fitness)
    
    async def _crossover(self, parent1: Payload, parent2: Payload) -> Payload:
        """
        تقاطع بين حمولتين
        """
        # نقطة القطع العشوائية
        cut_point = random.randint(1, min(len(parent1.payload), len(parent2.payload)) - 1)
        
        # دمج الحمولات
        child_payload_str = parent1.payload[:cut_point] + parent2.payload[cut_point:]
        
        # إذا كان الناتج طويلاً جداً، قصه
        if len(child_payload_str) > 500:
            child_payload_str = child_payload_str[:500]
        
        # إنشاء حمولة جديدة
        child = Payload(
            id=f"child_{parent1.id}_{parent2.id}",
            name=f"Crossover: {parent1.name} x {parent2.name}",
            type=parent1.type,
            payload=child_payload_str,
            encoding=parent1.encoding,
            description=f"Crossover of {parent1.name} and {parent2.name}",
            tags=parent1.tags + parent2.tags + ["crossover"]
        )
        
        return child
    
    async def _mutate(self, payload: Payload) -> Payload:
        """
        تحوير حمولة باستخدام تقنيات عشوائية
        """
        mutation_type = random.choice(["insert", "delete", "replace", "encode", "case"])
        
        if mutation_type == "insert":
            # إدخال أحرف عشوائية
            insert_pos = random.randint(0, len(payload.payload))
            random_char = random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
            new_payload_str = payload.payload[:insert_pos] + random_char + payload.payload[insert_pos:]
        
        elif mutation_type == "delete":
            # حذف أحرف عشوائية
            if len(payload.payload) > 10:
                delete_pos = random.randint(0, len(payload.payload) - 1)
                new_payload_str = payload.payload[:delete_pos] + payload.payload[delete_pos+1:]
            else:
                new_payload_str = payload.payload
        
        elif mutation_type == "replace":
            # استبدال أحرف
            if len(payload.payload) > 0:
                replace_pos = random.randint(0, len(payload.payload) - 1)
                random_char = random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                new_payload_str = payload.payload[:replace_pos] + random_char + payload.payload[replace_pos+1:]
            else:
                new_payload_str = payload.payload
        
        elif mutation_type == "encode":
            # ترميز عشوائي
            encoded = self._encoder.encode_payload(payload, "url")
            if encoded:
                new_payload_str = encoded.encoded
            else:
                new_payload_str = payload.payload
        
        elif mutation_type == "case":
            # تغيير حالة الأحرف
            new_payload_str = ''.join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in payload.payload
            )
        
        else:
            new_payload_str = payload.payload
        
        return Payload(
            id=f"mutated_{payload.id}",
            name=f"Mutated: {payload.name}",
            type=payload.type,
            payload=new_payload_str,
            encoding=payload.encoding,
            description=f"Mutated version with {mutation_type}",
            tags=payload.tags + ["mutated", f"mutated_{mutation_type}"]
        )
    
    async def _update_stats(self):
        """تحديث إحصائيات التطور"""
        if not self._population:
            return
        
        fitnesses = [ind.fitness for ind in self._population]
        successful = [ind for ind in self._population if ind.success_count > 0]
        
        stats = EvolutionStats(
            generation=self._generation,
            population_size=len(self._population),
            best_fitness=max(fitnesses),
            avg_fitness=sum(fitnesses) / len(fitnesses),
            total_mutations=sum(ind.mutation_count for ind in self._population),
            successful_individuals=len(successful),
            timestamp=datetime.now()
        )
        
        self._stats_history.append(stats)
        
        # الحفاظ على آخر 100 جيل فقط
        if len(self._stats_history) > 100:
            self._stats_history.pop(0)
    
    async def run_evolution(
        self,
        payload_type: PayloadType = PayloadType.XSS,
        max_generations: int = None,
        target_fitness: float = None,
        on_generation_complete: callable = None
    ) -> EvolutionIndividual:
        """
        تشغيل عملية التطور
        
        Args:
            payload_type: نوع الحمولة
            max_generations: الحد الأقصى للأجيال
            target_fitness: درجة اللياقة المستهدفة
            on_generation_complete: دالة callback عند اكتمال كل جيل
        
        Returns:
            أفضل فرد تم الوصول إليه
        """
        if max_generations is None:
            max_generations = self._params["max_generations"]
        
        if target_fitness is None:
            target_fitness = self._params["target_fitness"]
        
        self._running = True
        
        # إنشاء الجيل الأول
        await self.create_initial_population(payload_type)
        
        for gen in range(max_generations):
            if not self._running:
                break
            
            # تطور الجيل الجديد
            await self.evolve_generation()
            
            # التحقق من الوصول إلى الهدف
            if self._best_individual and self._best_individual.fitness >= target_fitness:
                logger.info(f"Target fitness {target_fitness} reached at generation {self._generation}")
                break
            
            # استدعاء callback
            if on_generation_complete:
                await on_generation_complete(self._generation, self._best_individual)
        
        self._running = False
        return self._best_individual
    
    async def record_success(self, payload_id: str, success: bool):
        """تسجيل نجاح أو فشل حمولة"""
        for individual in self._population:
            if individual.payload.id == payload_id:
                if success:
                    individual.success_count += 1
                else:
                    individual.fail_count += 1
                
                # تحديث اللياقة
                individual.fitness = await self._calculate_fitness(individual.payload)
                break
    
    def stop_evolution(self):
        """إيقاف عملية التطور"""
        self._running = False
        logger.info("Evolution stopped")
    
    async def get_best_payload(self) -> Optional[Payload]:
        """الحصول على أفضل حمولة تم الوصول إليها"""
        if self._best_individual:
            return self._best_individual.payload
        return None
    
    async def get_evolution_stats(self) -> Dict:
        """إحصائيات عملية التطور"""
        return {
            "current_generation": self._generation,
            "population_size": len(self._population),
            "best_fitness": self._best_individual.fitness if self._best_individual else 0,
            "total_generations": len(self._stats_history),
            "params": self._params,
            "history": [
                {
                    "generation": s.generation,
                    "best_fitness": s.best_fitness,
                    "avg_fitness": s.avg_fitness,
                    "successful": s.successful_individuals
                }
                for s in self._stats_history[-10:]
            ],
            "is_running": self._running
        }
    
    def update_params(self, new_params: Dict[str, Any]):
        """تحديث معاملات الخوارزمية"""
        self._params.update(new_params)
        logger.info(f"Evolution params updated: {new_params}")


# نسخة عالمية
_default_evolver = None


async def get_payload_evolver() -> PayloadEvolver:
    """الحصول على نسخة عالمية من تطور الحمولات"""
    global _default_evolver
    if _default_evolver is None:
        _default_evolver = PayloadEvolver()
        await _default_evolver.initialize_library()
    return _default_evolver

