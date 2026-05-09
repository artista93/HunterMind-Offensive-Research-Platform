
import asyncio
import re
import json
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urlparse
from dataclasses import dataclass

from .base_scanner import BaseScanner, ScanContext, Finding, Severity, Confidence

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    import aiohttp

import logging

logger = logging.getLogger(__name__)


@dataclass
class GraphQLQuery:
    """استعلام GraphQL"""
    name: str
    query: str
    type: str  # query, mutation, subscription
    description: str


class GraphQLScanner(BaseScanner):
    """
    فاحص ثغرات GraphQL API
    
    الميزات:
    - اكتشاف نقاط نهاية GraphQL
    - استخراج وتحليل Introspection
    - اكتشاف استعلامات عميقة (Deep Queries)
    - اختبار Batch Attacks
    - اكتشاف Field Duplication
    - تحليل Aliases
    - اختبار التعقيد (Complexity Attack)
    - كشف معلومات حساسة في Schema
    """
    
    # استعلامات Introspection
    INTROSPECTION_QUERIES = [
        GraphQLQuery(
            name="Full Introspection",
            query="""
            query IntrospectionQuery {
              __schema {
                types {
                  name
                  kind
                  description
                  fields {
                    name
                    type {
                      name
                      kind
                    }
                  }
                }
                queryType {
                  name
                  fields {
                    name
                    type {
                      name
                      kind
                    }
                  }
                }
                mutationType {
                  name
                  fields {
                    name
                    type {
                      name
                      kind
                    }
                  }
                }
              }
            }
            """,
            type="query",
            description="Complete schema introspection"
        ),
        GraphQLQuery(
            name="Type Introspection",
            query="""
            query TypeIntrospection($typeName: String!) {
              __type(name: $typeName) {
                name
                kind
                description
                fields {
                  name
                  type {
                    name
                    kind
                  }
                }
              }
            }
            """,
            type="query",
            description="Specific type introspection"
        ),
        GraphQLQuery(
            name="Field Introspection",
            query="""
            query FieldIntrospection {
              __schema {
                queryType {
                  fields {
                    name
                    args {
                      name
                      type {
                        name
                        kind
                      }
                    }
                  }
                }
              }
            }
            """,
            type="query",
            description="Query fields introspection"
        ),
    ]
    
    # بايلودات اختبار التعقيد
    COMPLEXITY_QUERIES = [
        GraphQLQuery(
            name="Deep Query",
            query="""
            query DeepQuery {
              user(id: 1) {
                friends {
                  friends {
                    friends {
                      friends {
                        friends {
                          friends {
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            """,
            type="query",
            description="Deeply nested query for complexity attack"
        ),
        GraphQLQuery(
            name="Field Duplication",
            query="""
            query FieldDuplication {
              user(id: 1) {
                name
                name
                name
                name
                name
                email
                email
                email
                email
                email
              }
            }
            """,
            type="query",
            description="Field duplication attack"
        ),
        GraphQLQuery(
            name="Alias Attack",
            query="""
            query AliasAttack {
              user1: user(id: 1) { name email }
              user2: user(id: 2) { name email }
              user3: user(id: 3) { name email }
              user4: user(id: 4) { name email }
              user5: user(id: 5) { name email }
              user6: user(id: 6) { name email }
              user7: user(id: 7) { name email }
              user8: user(id: 8) { name email }
            }
            """,
            type="query",
            description="Alias-based batch attack"
        ),
        GraphQLQuery(
            name="Batch Request",
            query="""
            [
              { "query": "query { user(id: 1) { name } }" },
              { "query": "query { user(id: 2) { email } }" },
              { "query": "query { posts { title } }" },
              { "query": "query { comments { body } }" }
            ]
            """,
            type="batch",
            description="Batch query attack"
        ),
    ]
    
    # أنماط الكشف عن GraphQL endpoints
    GRAPHQL_PATTERNS = [
        r"/graphql",
        r"/gql",
        r"/query",
        r"/api/graphql",
        r"/graphiql",
        r"/playground",
        r"/v2/graphql",
        r"/v3/graphql",
    ]
    
    # أنواع ميدانية حساسة
    SENSITIVE_FIELDS = [
        "password", "secret", "token", "key", "credit", "ssn", "social",
        "private", "internal", "admin", "root", "config", "credential",
        "email", "phone", "address", "birth", "passport", "driver",
    ]
    
    def __init__(
        self,
        rate_limit: float = 1.0,
        timeout: int = 30,
        max_retries: int = 2,
        enable_introspection: bool = True,
        enable_complexity_tests: bool = True,
        max_field_depth: int = 10
    ):
        super().__init__(
            name="GraphQLScanner",
            rate_limit=rate_limit,
            timeout=timeout,
            max_retries=max_retries
        )
        self._enable_introspection = enable_introspection
        self._enable_complexity_tests = enable_complexity_tests
        self._max_field_depth = max_field_depth
        self._session = None
        self._discovered_endpoints: Set[str] = set()
        self._schema_cache: Dict[str, Dict] = {}
    
    async def _get_session(self):
        """الحصول على جلسة HTTP"""
        if not self._session:
            if HTTPX_AVAILABLE:
                self._session = httpx.AsyncClient(
                    timeout=self.timeout,
                    follow_redirects=True,
                    verify=False
                )
            else:
                self._session = aiohttp.ClientSession()
        return self._session
    
    async def can_scan(self, context: ScanContext) -> bool:
        """التحقق من وجود GraphQL endpoint"""
        url = context.target.url.lower()
        
        for pattern in self.GRAPHQL_PATTERNS:
            if pattern in url:
                return True
        
        return False
    
    async def scan(self, context: ScanContext) -> List[Finding]:
        """تنفيذ فحص GraphQL"""
        findings = []
        
        # 1. اكتشاف نقاط نهاية GraphQL
        endpoints = await self._discover_graphql_endpoints(context)
        
        for endpoint in endpoints:
            self._discovered_endpoints.add(endpoint)
            
            # 2. اختبار Introspection
            if self._enable_introspection:
                introspection_findings = await self._test_introspection(endpoint, context)
                findings.extend(introspection_findings)
            
            # 3. اختبار التعقيد
            if self._enable_complexity_tests:
                complexity_findings = await self._test_complexity_attacks(endpoint, context)
                findings.extend(complexity_findings)
            
            # 4. تحليل الميدانات الحساسة
            sensitive_findings = await self._analyze_sensitive_fields(endpoint)
            findings.extend(sensitive_findings)
        
        return findings
    
    async def _discover_graphql_endpoints(self, context: ScanContext) -> List[str]:
        """اكتشاف نقاط نهاية GraphQL"""
        endpoints = []
        base_url = context.target.url.rstrip('/')
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for pattern in self.GRAPHQL_PATTERNS:
            test_url = f"{base}{pattern}"
            endpoints.append(test_url)
            
            # اختبار إضافي للنقاط النهاية الشائعة
            async with self._get_session() as session:
                try:
                    if HTTPX_AVAILABLE:
                        response = await session.get(test_url)
                        if response.status_code == 200:
                            logger.info(f"Discovered GraphQL endpoint: {test_url}")
                    else:
                        async with session.get(test_url) as resp:
                            if resp.status == 200:
                                logger.info(f"Discovered GraphQL endpoint: {test_url}")
                except:
                    pass
        
        return endpoints
    
    async def _test_introspection(self, endpoint: str, context: ScanContext) -> List[Finding]:
        """
        اختبار Introspection في GraphQL
        
        Introspection تسمح للمطورين بمعرفة هيكل الـ API.
        قد تكشف معلومات حساسة إذا كانت متاحة في الإنتاج.
        """
        findings = []
        
        for intro_query in self.INTROSPECTION_QUERIES:
            response = await self._send_graphql_request(endpoint, intro_query.query, context)
            
            if response:
                try:
                    data = json.loads(response) if isinstance(response, str) else response
                    
                    # التحقق من وجود بيانات introspection
                    if "__schema" in str(data):
                        self._schema_cache[endpoint] = data
                        
                        # اكتشاف معلومات حساسة في schema
                        sensitive_info = self._analyze_schema_for_sensitive_info(data)
                        
                        severity = Severity.MEDIUM if sensitive_info else Severity.INFO
                        confidence = Confidence.HIGH if sensitive_info else Confidence.CERTAIN
                        
                        finding = self.add_finding(
                            vulnerability_type="GraphQL Introspection Enabled",
                            severity=severity,
                            confidence=confidence,
                            url=endpoint,
                            payload=intro_query.name,
                            evidence=f"Introspection query '{intro_query.name}' returned schema data",
                            description=f"GraphQL introspection is enabled. This exposes the API schema and may leak sensitive information. {'Found sensitive fields: ' + ', '.join(sensitive_info) if sensitive_info else ''}",
                            remediation="Disable introspection in production environments. Use tools like graphql-disable-introspection or configure your GraphQL server to reject introspection queries.",
                            cvss_score=5.3 if sensitive_info else 4.0,
                            metadata={
                                "introspection_type": intro_query.name,
                                "sensitive_fields": sensitive_info
                            }
                        )
                        findings.append(finding)
                        break
                        
                except json.JSONDecodeError:
                    pass
        
        return findings
    
    async def _test_complexity_attacks(self, endpoint: str, context: ScanContext) -> List[Finding]:
        """
        اختبار هجمات التعقيد على GraphQL
        
        يمكن أن تسبب استعلامات معقدة استنزاف الموارد (DoS)
        """
        findings = []
        
        for complexity_query in self.COMPLEXITY_QUERIES:
            start_time = asyncio.get_event_loop().time()
            
            response = await self._send_graphql_request(endpoint, complexity_query.query, context)
            
            elapsed_time = asyncio.get_event_loop().time() - start_time
            
            if response:
                # إذا استغرق الطلب وقتاً طويلاً، قد يكون هناك ثغرة
                if elapsed_time > 5.0:
                    finding = self.add_finding(
                        vulnerability_type="GraphQL Complexity Attack (DoS)",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        url=endpoint,
                        payload=complexity_query.name,
                        evidence=f"Query '{complexity_query.name}' took {elapsed_time:.2f}s to execute",
                        description=f"Complex GraphQL query detected. The endpoint may be vulnerable to denial-of-service via query depth or field duplication attacks.",
                        remediation="Implement query complexity analysis, depth limiting, and rate limiting. Use tools like graphql-cost-analysis or graphql-depth-limit.",
                        cvss_score=6.5,
                        metadata={
                            "query_type": complexity_query.name,
                            "execution_time": elapsed_time,
                            "query": complexity_query.query[:200]
                        }
                    )
                    findings.append(finding)
                
                # التحقق من أخطاء محددة
                if response and "timeout" in str(response).lower():
                    finding = self.add_finding(
                        vulnerability_type="GraphQL Resource Exhaustion",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        url=endpoint,
                        payload=complexity_query.name,
                        evidence="Query caused timeout or resource exhaustion",
                        description="The GraphQL endpoint is vulnerable to resource exhaustion attacks via complex queries.",
                        remediation="Implement query cost analysis and timeout limits.",
                        cvss_score=7.5,
                        metadata={"query_type": complexity_query.name}
                    )
                    findings.append(finding)
        
        return findings
    
    async def _analyze_sensitive_fields(self, endpoint: str) -> List[Finding]:
        """تحليل وجود ميدانات حساسة في Schema"""
        findings = []
        
        if endpoint not in self._schema_cache:
            return findings
        
        schema = self._schema_cache[endpoint]
        sensitive_fields_found = self._analyze_schema_for_sensitive_info(schema)
        
        if sensitive_fields_found:
            finding = self.add_finding(
                vulnerability_type="Sensitive Fields Exposed in GraphQL Schema",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                url=endpoint,
                description=f"Schema exposes sensitive data fields: {', '.join(sensitive_fields_found)}",
                remediation="Review and remove sensitive fields from the public schema. Use schema filtering or field-level permissions.",
                cvss_score=5.0,
                metadata={"sensitive_fields": sensitive_fields_found}
            )
            findings.append(finding)
        
        return findings
    
    def _analyze_schema_for_sensitive_info(self, schema: Dict) -> List[str]:
        """تحليل الـ Schema بحثاً عن معلومات حساسة"""
        sensitive_fields = []
        
        # البحث في أنواع الـ Schema
        types = schema.get("data", {}).get("__schema", {}).get("types", [])
        if not types:
            types = schema.get("__schema", {}).get("types", [])
        
        for type_info in types:
            fields = type_info.get("fields", [])
            for field in fields:
                field_name = field.get("name", "").lower()
                
                for sensitive in self.SENSITIVE_FIELDS:
                    if sensitive in field_name:
                        if field_name not in sensitive_fields:
                            sensitive_fields.append(field_name)
        
        return sensitive_fields
    
    async def _send_graphql_request(
        self,
        endpoint: str,
        query: str,
        context: ScanContext
    ) -> Optional[str]:
        """
        إرسال طلب GraphQL
        
        يدعم استعلامات فردية ومتعددة (batch)
        """
        session = await self._get_session()
        
        # إذا كان الاستعلام هو طلب batch
        if query.strip().startswith("["):
            payload = json.loads(query)
        else:
            payload = {"query": query}
        
        headers = context.target.headers.copy()
        headers["Content-Type"] = "application/json"
        
        try:
            if HTTPX_AVAILABLE:
                response = await session.post(
                    endpoint,
                    json=payload,
                    headers=headers
                )
                return response.text
            else:
                async with session.post(
                    endpoint,
                    json=payload,
                    headers=headers
                ) as resp:
                    return await resp.text()
                    
        except Exception as e:
            logger.debug(f"GraphQL request error: {e}")
            return None
    
    async def test_field_suggestions(self, endpoint: str, context: ScanContext) -> List[str]:
        """
        اختبار اقتراحات الميدانات (Field Suggestions)
        
        بعض خوادم GraphQL تقترح أسماء ميدانات عند الخطأ، مما يكشف معلومات
        """
        suggestions = []
        
        # استعلام غير صحيح لتحفيز الاقتراحات
        test_query = """
        query {
          invalidField
        }
        """
        
        response = await self._send_graphql_request(endpoint, test_query, context)
        
        if response:
            # البحث عن اقتراحات في رسالة الخطأ
            patterns = [
                r"Did you mean (.*?)[\.\?]",
                r"Did you mean ‘(.+)’",
                r"Perhaps you meant (.*?)[\.\?]",
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, response, re.I)
                suggestions.extend(matches)
        
        return suggestions
    
    async def close(self):
        """إغلاق الجلسة"""
        if self._session:
            if HTTPX_AVAILABLE:
                await self._session.aclose()
            else:
                await self._session.close()
            self._session = None

