
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import random

import logging

logger = logging.getLogger(__name__)


@dataclass
class StrategyGene:
    """جين استراتيجي"""
    name: str
    value: Any
    mutation_rate: float
    possible_values: List[Any]


@dataclass
class StrategyChromosome:
    """كروموسوم استراتيجي"""
    id: str
    genes: Dict[str, StrategyGene]
    fitness: float
    generation: int
    parent_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)


class StrategyEvolver:
    """
    مطور الاستراتيجيات المتقدم
    
    الميزات:
    - تطور الاستراتيجيات باستخدام الخوارزميات الجينية
    - اختيار الأفضل (selection)
    - تقاطع (crossover) وتحوير (mutation)
    - تقييم اللياقة (fitness)
    - تتبع الأجيال
    """
    
    def __init__(self, population_size: int = 20, mutation_rate: float = 0.1):
        self._population_size = population_size
        self._mutation_rate = mutation_rate
        self._population: List[StrategyChromosome] = []
        self._generation = 0
        self._best_fitness_history: List[float] = []
        
        # تهيئة الجينات الأساسية
        self._init_default_genes()
        
        logger.info("StrategyEvolver initialized")
    
    def _init_default_genes(self):
        """تهيئة الجينات الأساسية"""
        self._base_genes = {
            "scan_depth": StrategyGene(
                name="scan_depth",
                value=3,
                mutation_rate=0.2,
                possible_values=[1, 2, 3, 4, 5]
            ),
            "concurrent_requests": StrategyGene(
                name="concurrent_requests",
                value=10,
                mutation_rate=0.15,
                possible_values=[5, 10, 15, 20, 25]
            ),
            "timeout_seconds": StrategyGene(
                name="timeout_seconds",
                value=30,
                mutation_rate=0.1,
                possible_values=[15, 30, 45, 60, 90]
            ),
            "retry_attempts": StrategyGene(
                name="retry_attempts",
                value=3,
                mutation_rate=0.1,
                possible_values=[1, 2, 3, 4, 5]
            ),
            "stealth_level": StrategyGene(
                name="stealth_level",
                value=0.5,
                mutation_rate=0.2,
                possible_values=[0.0, 0.25, 0.5, 0.75, 1.0]
            )
        }
    
    async def initialize_population(self):
        """تهيئة الجيل الأول من السكان"""
        self._population = []
        
        for i in range(self._population_size):
            chromosome = await self._create_random_chromosome()
            self._population.append(chromosome)
        
        self._generation = 0
        logger.info(f"Population initialized with {len(self._population)} chromosomes")
    
    async def _create_random_chromosome(self) -> StrategyChromosome:
        """إنشاء كروموسوم عشوائي"""
        import uuid
        chromosome_id = str(uuid.uuid4())[:8]
        
        genes = {}
        for name, base_gene in self._base_genes.items():
            value = random.choice(base_gene.possible_values)
            genes[name] = StrategyGene(
                name=name,
                value=value,
                mutation_rate=base_gene.mutation_rate,
                possible_values=base_gene.possible_values
            )
        
        return StrategyChromosome(
            id=chromosome_id,
            genes=genes,
            fitness=0.0,
            generation=0
        )
    
    async def evaluate_fitness(
        self,
        chromosome: StrategyChromosome,
        performance_metrics: Dict[str, float]
    ) -> float:
        """
        تقييم لياقة كروموسوم استراتيجي
        
        Args:
            chromosome: الكروموسوم
            performance_metrics: مقاييس الأداء
        
        Returns:
            درجة اللياقة (0-1)
        """
        fitness = 0.0
        
        # مقاييس الأداء المطلوبة
        success_rate = performance_metrics.get("success_rate", 0)
        response_time = performance_metrics.get("response_time", 0)
        resource_usage = performance_metrics.get("resource_usage", 0)
        
        # حساب اللياقة
        fitness += success_rate * 0.5
        
        if response_time > 0:
            time_score = max(0, 1 - response_time / 30)
            fitness += time_score * 0.25
        
        if resource_usage > 0:
            resource_score = max(0, 1 - resource_usage)
            fitness += resource_score * 0.25
        
        chromosome.fitness = fitness
        return fitness
    
    async def evolve(self) -> List[StrategyChromosome]:
        """
        تطور الجيل التالي
        
        Returns:
            الجيل الجديد من السكان
        """
        if not self._population:
            await self.initialize_population()
        
        # ترتيب حسب اللياقة
        self._population.sort(key=lambda x: x.fitness, reverse=True)
        
        # تسجيل أفضل لياقة
        best_fitness = self._population[0].fitness if self._population else 0
        self._best_fitness_history.append(best_fitness)
        
        # اختيار النخبة (أفضل 20%)
        elite_count = max(1, int(self._population_size * 0.2))
        elite = self._population[:elite_count]
        
        # إنشاء الجيل الجديد
        new_population = elite.copy()
        
        while len(new_population) < self._population_size:
            # اختيار الوالدين (بطولة)
            parent1 = await self._tournament_selection()
            parent2 = await self._tournament_selection()
            
            # تقاطع
            child = await self._crossover(parent1, parent2)
            
            # تحوير
            child = await self._mutate(child)
            
            new_population.append(child)
        
        self._population = new_population
        self._generation += 1
        
        logger.info(f"Generation {self._generation} evolved, best fitness = {best_fitness:.3f}")
        return self._population
    
    async def _tournament_selection(self, tournament_size: int = 3) -> StrategyChromosome:
        """اختيار بواسطة البطولة"""
        participants = random.sample(self._population, min(tournament_size, len(self._population)))
        return max(participants, key=lambda x: x.fitness)
    
    async def _crossover(
        self,
        parent1: StrategyChromosome,
        parent2: StrategyChromosome
    ) -> StrategyChromosome:
        """تقاطع بين والدين"""
        import uuid
        child_id = str(uuid.uuid4())[:8]
        
        genes = {}
        for name in self._base_genes.keys():
            # اختيار عشوائي من أحد الوالدين
            if random.random() > 0.5:
                value = parent1.genes[name].value
            else:
                value = parent2.genes[name].value
            
            genes[name] = StrategyGene(
                name=name,
                value=value,
                mutation_rate=self._base_genes[name].mutation_rate,
                possible_values=self._base_genes[name].possible_values
            )
        
        return StrategyChromosome(
            id=child_id,
            genes=genes,
            fitness=0.0,
            generation=self._generation + 1,
            parent_id=parent1.id
        )
    
    async def _mutate(self, chromosome: StrategyChromosome) -> StrategyChromosome:
        """تحوير الكروموسوم"""
        for name, gene in chromosome.genes.items():
            if random.random() < gene.mutation_rate:
                # اختيار قيمة جديدة عشوائية
                possible = gene.possible_values
                current = gene.value
                new_value = random.choice([v for v in possible if v != current])
                gene.value = new_value
        
        return chromosome
    
    async def get_best_strategy(self) -> Optional[StrategyChromosome]:
        """الحصول على أفضل استراتيجية حالية"""
        if not self._population:
            return None
        
        return max(self._population, key=lambda x: x.fitness)
    
    async def get_strategy_genes(self, chromosome: StrategyChromosome) -> Dict[str, Any]:
        """الحصول على قيم الجينات للاستراتيجية"""
        return {name: gene.value for name, gene in chromosome.genes.items()}
    
    async def get_evolution_stats(self) -> Dict:
        """إحصائيات التطور"""
        if not self._population:
            return {"generation": 0, "population_size": 0}
        
        return {
            "generation": self._generation,
            "population_size": len(self._population),
            "best_fitness": max(c.fitness for c in self._population),
            "average_fitness": sum(c.fitness for c in self._population) / len(self._population),
            "best_fitness_history": self._best_fitness_history[-10:],
            "gene_ranges": {
                name: {
                    "min": min(c.genes[name].value for c in self._population),
                    "max": max(c.genes[name].value for c in self._population),
                    "avg": sum(c.genes[name].value for c in self._population) / len(self._population)
                }
                for name in self._base_genes.keys()
            }
        }

