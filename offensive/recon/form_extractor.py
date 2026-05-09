
import re
import json
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime

try:
    from bs4 import BeautifulSoup
    BEAUTIFULSOUP_AVAILABLE = True
except ImportError:
    BEAUTIFULSOUP_AVAILABLE = False

import logging

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """حقل في نموذج"""
    name: str
    type: str  # text, password, email, hidden, file, submit, etc.
    value: Optional[str] = None
    placeholder: Optional[str] = None
    required: bool = False
    max_length: Optional[int] = None
    min_length: Optional[int] = None
    pattern: Optional[str] = None
    options: List[str] = field(default_factory=list)  # للـ select


@dataclass
class ExtractedForm:
    """نموذج مستخرج"""
    id: Optional[str]
    name: Optional[str]
    action: str
    method: str  # GET, POST
    enctype: str  # application/x-www-form-urlencoded, multipart/form-data, text/plain
    fields: List[FormField] = field(default_factory=list)
    has_file_upload: bool = False
    has_password_field: bool = False
    has_csrf_token: bool = False
    csrf_token_name: Optional[str] = None
    action_url: str = ""
    source_url: str = ""


@dataclass
class FormAnalysisResult:
    """نتائج تحليل النماذج"""
    url: str
    analyzed_at: datetime
    forms: List[ExtractedForm] = field(default_factory=list)
    total_forms: int = 0
    vulnerable_patterns: List[Dict] = field(default_factory=list)


class FormExtractor:
    """
    مستخرج النماذج المتقدم
    
    الميزات:
    - استخراج جميع النماذج من HTML
    - تحليل حقول النماذج (أنواع، قيود)
    - كشف حقول CSRF tokens
    - كشف رفع الملفات
    - كشف حقول كلمة المرور
    - تحليل الأمان الأساسي للنماذج
    - دعم BeautifulSoup للتحليل المتقدم
    """
    
    # أنماط كشف CSRF tokens
    CSRF_PATTERNS = [
        r'csrf',
        r'token',
        r' authenticity',
        r'xsrf',
        r'_token',
        r'csrfmiddlewaretoken',
        r'csrf_token',
    ]
    
    # أنواع الحقول الخاصة
    SENSITIVE_FIELD_TYPES = ['password', 'credit-card', 'ssn', 'tax']
    
    def __init__(self, use_beautifulsoup: bool = True):
        self._use_beautifulsoup = use_beautifulsoup and BEAUTIFULSOUP_AVAILABLE
        self._processed_urls: Set[str] = set()
        
        logger.info(f"FormExtractor initialized (beautifulsoup={self._use_beautifulsoup})")
    
    async def extract_from_html(
        self,
        html: str,
        base_url: str,
        extract_inline_js: bool = False
    ) -> FormAnalysisResult:
        """
        استخراج النماذج من HTML
        
        Args:
            html: محتوى HTML
            base_url: الرابط الأساسي للصفحة
            extract_inline_js: استخراج نماذج من كود JS المضمن
        
        Returns:
            نتائج تحليل النماذج
        """
        result = FormAnalysisResult(
            url=base_url,
            analyzed_at=datetime.now()
        )
        
        if self._use_beautifulsoup:
            forms = await self._extract_with_bs4(html, base_url)
        else:
            forms = await self._extract_with_regex(html, base_url)
        
        result.forms = forms
        result.total_forms = len(forms)
        
        # تحليل الأمان
        result.vulnerable_patterns = await self._analyze_security(forms)
        
        logger.info(f"Extracted {len(forms)} forms from {base_url}")
        
        return result
    
    async def _extract_with_bs4(self, html: str, base_url: str) -> List[ExtractedForm]:
        """استخراج النماذج باستخدام BeautifulSoup"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            # استخراج خصائص النموذج
            form_id = form.get('id')
            form_name = form.get('name')
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            enctype = form.get('enctype', 'application/x-www-form-urlencoded')
            
            # تحويل action إلى رابط مطلق
            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url
            
            # استخراج الحقول
            fields = []
            has_file_upload = False
            has_password_field = False
            has_csrf_token = False
            csrf_token_name = None
            
            # جميع عناصر الإدخال
            for input_elem in form.find_all(['input', 'textarea', 'select']):
                field = await self._extract_field_bs4(input_elem)
                if field:
                    fields.append(field)
                    
                    if field.type == 'file':
                        has_file_upload = True
                    
                    if field.type == 'password':
                        has_password_field = True
                    
                    # كشف CSRF token
                    for pattern in self.CSRF_PATTERNS:
                        if field.name and pattern in field.name.lower():
                            has_csrf_token = True
                            csrf_token_name = field.name
                            break
            
            extracted_form = ExtractedForm(
                id=form_id,
                name=form_name,
                action=action,
                method=method,
                enctype=enctype,
                fields=fields,
                has_file_upload=has_file_upload,
                has_password_field=has_password_field,
                has_csrf_token=has_csrf_token,
                csrf_token_name=csrf_token_name,
                action_url=action_url,
                source_url=base_url
            )
            
            forms.append(extracted_form)
        
        return forms
    
    async def _extract_field_bs4(self, element) -> Optional[FormField]:
        """استخراج حقل نموذج باستخدام BeautifulSoup"""
        tag_name = element.name
        
        if tag_name == 'input':
            field_type = element.get('type', 'text').lower()
            name = element.get('name')
            value = element.get('value')
            placeholder = element.get('placeholder')
            required = element.get('required') is not None
            max_length = element.get('maxlength')
            min_length = element.get('minlength')
            pattern = element.get('pattern')
            
            if not name:
                return None
            
            return FormField(
                name=name,
                type=field_type,
                value=value,
                placeholder=placeholder,
                required=required,
                max_length=int(max_length) if max_length else None,
                min_length=int(min_length) if min_length else None,
                pattern=pattern
            )
        
        elif tag_name == 'textarea':
            name = element.get('name')
            placeholder = element.get('placeholder')
            required = element.get('required') is not None
            max_length = element.get('maxlength')
            
            if not name:
                return None
            
            return FormField(
                name=name,
                type='textarea',
                placeholder=placeholder,
                required=required,
                max_length=int(max_length) if max_length else None
            )
        
        elif tag_name == 'select':
            name = element.get('name')
            required = element.get('required') is not None
            options = []
            
            for option in element.find_all('option'):
                option_value = option.get('value', option.text)
                options.append(option_value)
            
            if not name:
                return None
            
            return FormField(
                name=name,
                type='select',
                options=options,
                required=required
            )
        
        return None
    
    async def _extract_with_regex(self, html: str, base_url: str) -> List[ExtractedForm]:
        """استخراج النماذج باستخدام Regular Expressions (fallback)"""
        forms = []
        
        # نمط استخراج النماذج
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.I | re.DOTALL)
        
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            form_content = form_match.group(1)
            
            # استخراج خصائص النموذج
            form_id = self._extract_attribute(form_html, 'id')
            form_name = self._extract_attribute(form_html, 'name')
            action = self._extract_attribute(form_html, 'action') or ''
            method = (self._extract_attribute(form_html, 'method') or 'GET').upper()
            enctype = self._extract_attribute(form_html, 'enctype') or 'application/x-www-form-urlencoded'
            
            # تحويل action إلى رابط مطلق
            if action:
                action_url = urljoin(base_url, action)
            else:
                action_url = base_url
            
            # استخراج الحقول
            fields = []
            has_file_upload = False
            has_password_field = False
            has_csrf_token = False
            csrf_token_name = None
            
            # استخراج الـ inputs
            input_pattern = re.compile(r'<input[^>]*>', re.I)
            for input_match in input_pattern.finditer(form_content):
                input_html = input_match.group(0)
                field = await self._extract_field_regex(input_html)
                if field:
                    fields.append(field)
                    
                    if field.type == 'file':
                        has_file_upload = True
                    if field.type == 'password':
                        has_password_field = True
                    
                    for pattern in self.CSRF_PATTERNS:
                        if field.name and pattern in field.name.lower():
                            has_csrf_token = True
                            csrf_token_name = field.name
            
            # استخراج textareas
            textarea_pattern = re.compile(r'<textarea[^>]*>(.*?)</textarea>', re.I | re.DOTALL)
            for textarea_match in textarea_pattern.finditer(form_content):
                textarea_html = textarea_match.group(0)
                name = self._extract_attribute(textarea_html, 'name')
                if name:
                    fields.append(FormField(
                        name=name,
                        type='textarea',
                        placeholder=self._extract_attribute(textarea_html, 'placeholder'),
                        required=self._extract_attribute(textarea_html, 'required') is not None
                    ))
            
            # استخراج selects
            select_pattern = re.compile(r'<select[^>]*>(.*?)</select>', re.I | re.DOTALL)
            for select_match in select_pattern.finditer(form_content):
                select_html = select_match.group(0)
                name = self._extract_attribute(select_html, 'name')
                if name:
                    options = []
                    option_pattern = re.compile(r'<option[^>]*>(.*?)</option>', re.I)
                    for opt_match in option_pattern.finditer(select_match.group(1)):
                        options.append(opt_match.group(1).strip())
                    
                    fields.append(FormField(
                        name=name,
                        type='select',
                        options=options,
                        required=self._extract_attribute(select_html, 'required') is not None
                    ))
            
            extracted_form = ExtractedForm(
                id=form_id,
                name=form_name,
                action=action,
                method=method,
                enctype=enctype,
                fields=fields,
                has_file_upload=has_file_upload,
                has_password_field=has_password_field,
                has_csrf_token=has_csrf_token,
                csrf_token_name=csrf_token_name,
                action_url=action_url,
                source_url=base_url
            )
            
            forms.append(extracted_form)
        
        return forms
    
    async def _extract_field_regex(self, input_html: str) -> Optional[FormField]:
        """استخراج حقل من input HTML باستخدام regex"""
        name = self._extract_attribute(input_html, 'name')
        if not name:
            return None
        
        field_type = self._extract_attribute(input_html, 'type') or 'text'
        value = self._extract_attribute(input_html, 'value')
        placeholder = self._extract_attribute(input_html, 'placeholder')
        required = self._extract_attribute(input_html, 'required') is not None
        max_length = self._extract_attribute(input_html, 'maxlength')
        pattern = self._extract_attribute(input_html, 'pattern')
        
        return FormField(
            name=name,
            type=field_type.lower(),
            value=value,
            placeholder=placeholder,
            required=required,
            max_length=int(max_length) if max_length else None,
            pattern=pattern
        )
    
    def _extract_attribute(self, tag_html: str, attr_name: str) -> Optional[str]:
        """استخراج قيمة خاصية من علامة HTML"""
        # أنماط مختلفة للخاصية
        patterns = [
            rf'{attr_name}=["\']([^"\']*)["\']',
            rf"{attr_name}=['\"]([^'\"]*)['\"]",
            rf'{attr_name}=([^\s>]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, tag_html, re.I)
            if match:
                return match.group(1)
        
        return None
    
    async def _analyze_security(self, forms: List[ExtractedForm]) -> List[Dict]:
        """تحليل أمان النماذج"""
        vulnerabilities = []
        
        for form in forms:
            # 1. نماذج GET مع بيانات حساسة
            if form.method == 'GET':
                for field in form.fields:
                    if field.type in ['password', 'credit-card']:
                        vulnerabilities.append({
                            "type": "Sensitive Data in GET Form",
                            "severity": "HIGH",
                            "form_action": form.action_url,
                            "details": f"Form uses GET method with {field.type} field '{field.name}'",
                            "remediation": "Use POST method for sensitive data"
                        })
                        break
            
            # 2. نماذج بدون CSRF protection
            if form.method == 'POST' and not form.has_csrf_token:
                vulnerabilities.append({
                    "type": "Missing CSRF Protection",
                    "severity": "MEDIUM",
                    "form_action": form.action_url,
                    "details": "Form lacks CSRF token",
                    "remediation": "Implement CSRF tokens for all state-changing requests"
                })
            
            # 3. رفع الملفات بدون قيود (تحتاج تحليل إضافي)
            if form.has_file_upload:
                vulnerabilities.append({
                    "type": "File Upload Capability",
                    "severity": "INFO",
                    "form_action": form.action_url,
                    "details": "Form supports file uploads",
                    "remediation": "Implement file type validation and size limits"
                })
            
            # 4. نماذج بدون HTTPS
            if form.action_url.startswith('http://'):
                vulnerabilities.append({
                    "type": "Insecure Form Submission",
                    "severity": "MEDIUM",
                    "form_action": form.action_url,
                    "details": "Form submits over HTTP (not HTTPS)",
                    "remediation": "Use HTTPS for all form submissions"
                })
            
            # 5. حقول hidden
            hidden_fields = [f for f in form.fields if f.type == 'hidden']
            if hidden_fields:
                vulnerabilities.append({
                    "type": "Hidden Fields Present",
                    "severity": "INFO",
                    "form_action": form.action_url,
                    "details": f"Form contains {len(hidden_fields)} hidden fields: {[f.name for f in hidden_fields]}",
                    "remediation": "Review hidden fields for sensitive data"
                })
        
        return vulnerabilities
    
    async def get_form_summary(self, forms: List[ExtractedForm]) -> Dict:
        """ملخص النماذج"""
        if not forms:
            return {"total": 0}
        
        methods = {}
        enctypes = {}
        field_types = {}
        
        for form in forms:
            methods[form.method] = methods.get(form.method, 0) + 1
            enctypes[form.enctype] = enctypes.get(form.enctype, 0) + 1
            
            for field in form.fields:
                field_types[field.type] = field_types.get(field.type, 0) + 1
        
        return {
            "total": len(forms),
            "methods": methods,
            "enctypes": enctypes,
            "field_types": field_types,
            "has_csrf": sum(1 for f in forms if f.has_csrf_token),
            "has_file_upload": sum(1 for f in forms if f.has_file_upload),
            "has_password": sum(1 for f in forms if f.has_password_field),
        }
    
    async def generate_test_data(self, form: ExtractedForm) -> Dict[str, str]:
        """
        توليد بيانات اختبار للنموذج
        
        Args:
            form: النموذج المستخرج
        
        Returns:
            قاموس بقيم الاختبار للحقول
        """
        test_data = {}
        
        for field in form.fields:
            if field.type == 'email':
                test_data[field.name] = 'test@example.com'
            elif field.type == 'password':
                test_data[field.name] = 'Test123!@#'
            elif field.type == 'text' or field.type == 'textarea':
                if 'name' in field.name.lower():
                    test_data[field.name] = 'Test User'
                elif 'search' in field.name.lower():
                    test_data[field.name] = 'test'
                else:
                    test_data[field.name] = 'test_value'
            elif field.type == 'number':
                test_data[field.name] = '123'
            elif field.type == 'tel':
                test_data[field.name] = '+1234567890'
            elif field.type == 'url':
                test_data[field.name] = 'https://example.com'
            elif field.type == 'hidden':
                if field.value:
                    test_data[field.name] = field.value
                else:
                    test_data[field.name] = ''
            elif field.type == 'checkbox':
                test_data[field.name] = 'on'
            elif field.type == 'radio':
                if field.options:
                    test_data[field.name] = field.options[0]
            elif field.type == 'select':
                if field.options:
                    test_data[field.name] = field.options[0]
            else:
                test_data[field.name] = 'test'
        
        return test_data


# نسخة عالمية
async def get_form_extractor() -> FormExtractor:
    """الحصول على نسخة من مستخرج النماذج"""
    return FormExtractor()

