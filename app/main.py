from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import subprocess
import tempfile
import os
import re
import json
import hashlib
import ast
from datetime import datetime
from typing import List, Optional, Dict, Any

app = FastAPI(title="Advanced Code Security Scanner", version="6.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Enhanced security patterns with comprehensive coverage
SECURITY_PATTERNS = {
    "sql_injection": [
        # Basic SQL injection patterns
        r"(SELECT\s.*\sFROM\s.*\sWHERE\s.*\+\s*[^?])",
        r"(SELECT\s.*\sFROM\s.*\sWHERE\s.*['\"]\s*\+\s*)",
        r"(db\.(query|execute)\s*\(\s*[^?]*\+)",
        # F-string SQL injection
        r'f["\']SELECT.*\{[^}]+\}.*["\']',
        r'f["\'].*\{[^}]+\}.*WHERE.*["\']',
        r'f["\'].*\{[^}]+\}.*VALUES.*["\']',
        # String formatting SQL injection
        r'["\']SELECT.*%s.*["\']',
        r'["\']SELECT.*\{.*\}.*["\']',
        # Common SQL patterns with user input
        r"(SELECT\s.*\*.*FROM.*WHERE.*=.*['\"])",
        r"(INSERT\s+INTO.*VALUES.*\+)",
        r"(UPDATE\s+.*SET.*=.*\+)",
        r"(DELETE\s+FROM.*WHERE.*\+)",
    ],
    "command_injection": [
        # ANY dangerous command execution
        r"os\.system\s*\(\s*[^)]+\)",
        r"subprocess\.(call|run|Popen)\s*\(\s*[^)]+\)",
        r"eval\s*\(\s*[^)]+\)",
        r"exec\s*\(\s*[^)]+\)",
        r"Runtime\.getRuntime\(\)\.exec\([^)]+\)",
        r"ProcessBuilder\([^)]+\)",
    ],
    "dangerous_commands": [
        # Specific dangerous commands
        r"rm\s+-rf",
        r"format\s+/",
        r"del\s+/[A-Z]:",
        r"chmod\s+777",
        r"dd\s+if=.*of=.*",
        r"mkfs",
        r"shred",
        r"mv\s+.*/dev/null",
    ],
    "file_operations": [
        r"(open\s*\([^)]*[wax][^)]*\))",
        r"(shutil\.(copy|move|rmtree))",
        r"(os\.(remove|unlink|rename)\s*\()",
        r"(unlink\s*\()",
    ],
    "deserialization": [
        r"(pickle\.loads?\s*\()",
        r"(marshal\.loads?\s*\()",
        r"(yaml\.load\s*\()",
        r"(json\.loads?\s*\(\s*[^)]*\)\))",
    ],
    "hardcoded_secrets": [
        r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]",
        r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]",
        r"(?i)secret\s*[:=]\s*['\"][^'\"]+['\"]",
        r"(?i)token\s*[:=]\s*['\"][^'\"]+['\"]",
        r"connect\s*\(\s*[^,]+,\s*[^,]+,\s*['\"][^'\"]+['\"]",
        r"sk-[a-zA-Z0-9]{24,}",
        r"AKIA[0-9A-Z]{16}",
        r"['\"][0-9a-f]{32}['\"]",
        r"['\"][0-9a-f]{64}['\"]",
    ],
    "suspicious_urls": [
        r"(http://[^\s]+)",
        r"(https://[^\s]+)",
        r"(base64\.b64decode\s*\()",
        r"(urllib\.(request|2)?\.urlopen\s*\()",
        r"(requests\.(get|post|put|delete)\s*\()",
    ]
}

# Multi-language patterns
MULTI_LANGUAGE_PATTERNS = {
    "java_deserialization": [
        r"(readObject\s*\()",
        r"(ObjectInputStream\s*\()",
        r"(deserialize\s*\()",
        r"(\.readObject\s*\()",
        r"(Serializable)",
        r"(rmi://)",
        r"(URLClassLoader)"
    ],
    "java_command_injection": [
        r"(Runtime\.getRuntime\s*\()",
        r"(\.exec\s*\()",
        r"(ProcessBuilder\s*\()",
        r"(System\.exec\s*\()"
    ],
    "javascript_injection": [
        r"(eval\s*\()",
        r"(Function\s*\()",
        r"(setTimeout\s*\(\s*[^)]*\s*)",
        r"(setInterval\s*\(\s*[^)]*\s*)",
        r"(document\.write\s*\()",
        r"(innerHTML\s*=)"
    ],
    "c_cpp_memory_issues": [
        r"(strcpy\s*\()",
        r"(gets\s*\()",
        r"(sprintf\s*\()",
        r"(malloc\s*\()",
        r"(free\s*\()",
        r"(buffer\s*\[)",
        r"(memcpy\s*\()"
    ]
}

# Enhanced patterns for specific vulnerabilities
ENHANCED_PATTERNS = {
    "file_upload_risks": [
        r"(req\.files\..*\.mv\s*\()",
        r"(\.mv\s*\(\s*['\"][^'\"]*\+.*\.name)",
        r"(multer\s*\(\s*\{.*dest\s*:\s*['\"][^'\"]*['\"])",
        r"(fs\.(writeFile|appendFile).*req\..*name)",
    ],
    "path_traversal": [
        r"(\.\./)",
        r"(\.\.\\)",
        r"(req\..*\.name.*path)",
        r"(req\..*\.path.*join)",
    ],
    "insecure_cors": [
        r"cors\s*\(\s*\{[^}]*origin\s*:\s*['\"]['\*]['\"]",
        r"Access-Control-Allow-Origin\s*:\s*['\"]['\*]['\"]",
        r"cors\s*\(\s*\{[^}]*origin\s*:\s*true",
    ],
    "xss_vulnerabilities": [
        r"innerHTML\s*=\s*[^;]+",
        r"document\.write\s*\([^)]+\)",
        r"<script>[^<]*const[^<]*=['\"][^<]*</script>",
        r"<script>[^<]*API_KEY[^<]*=['\"][^<]*</script>",
    ],
    "unsafe_file_operations": [
        r"req\.files\..*\.mv\s*\(",
        r"fs\.(writeFile|appendFile|createWriteStream)\s*\(\s*[^,]+,\s*req\.",
    ],
    "insecure_authentication": [
        r"localStorage\.[^=]*=\s*[^;]*(password|token|key)",
        r"sessionStorage\.[^=]*=\s*[^;]*(password|token|key)",
        r"cookie\s*=\s*[^;]*(password|token|key)",
    ],
    "information_disclosure": [
        r"console\.log\(.*req\.body",
        r"console\.log\(.*password",
        r"logger\.info\(.*secret",
        r"print\(.*token",
    ]
}

# Safe pattern indicators to reduce false positives
SAFE_PATTERNS = {
    "safe_sql_indicators": [
        r"db\.execute\([^?]*\?",  # Parameterized queries
        r"db\.query\([^?]*\?",    # Parameterized queries
        r"\(\s*\?\s*,\s*\[",      # Question mark placeholders
        r"\(\s*%s\s*,\s*\[",      # %s placeholders
        r"prepareStatement",       # Java prepared statements
    ],
    "safe_command_indicators": [
        r"subprocess\.run\(\[[^\]]+\]",  # Argument arrays
        r"shlex\.split",                 # Safe argument splitting
        r"shell\s*=\s*False",            # Explicit shell=False
        r"ProcessBuilder\(\[[^\]]+\]",   # Java ProcessBuilder with arrays
    ]
}

# Advanced secrets detection
SECRETS_PATTERNS = {
    "api_keys": [
        r"['\"](sk-[a-zA-Z0-9]{24,})['\"]",
        r"['\"](AKIA[0-9A-Z]{16})['\"]",
        r"['\"](gh[pousr]_[a-zA-Z0-9]{36})['\"]",
        r"['\"](xox[pbar]-[a-zA-Z0-9]{10,48})['\"]",
    ],
    "credentials": [
        r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]",
        r"(?i)api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]",
        r"(?i)secret\s*[:=]\s*['\"][^'\"]+['\"]",
        r"connect\s*\(\s*[^,]+,\s*[^,]+,\s*['\"][^'\"]+['\"]",
    ],
    "tokens": [
        r"['\"](eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9]{10,}\.[a-zA-Z0-9_-]{10,})['\"]",  # JWT
        r"['\"]([a-f0-9]{32})['\"]",  # MD5-like
        r"['\"]([a-f0-9]{64})['\"]",  # SHA256-like
    ]
}

# LLM-specific patterns
LLM_PATTERNS = {
    "prompt_injection": [
        r"(?i)ignore previous instructions",
        r"(?i)system prompt",
        r"(?i)role play as",
        r"(?i)you are now",
    ],
    "unsafe_llm_output": [
        r"eval\s*\(\s*llm_response",
        r"exec\s*\(\s*generated_code",
        r"subprocess\.run\(.*ai_output",
    ]
}

class CodeAnalysisRequest(BaseModel):
    code: str
    language: str = "python"
    is_llm_output: bool = False

class SecurityIssue(BaseModel):
    type: str
    pattern: str
    line_number: int
    severity: str
    description: str
    remediation: str
    code_snippet: str

class AnalysisResult(BaseModel):
    overall_risk: str
    score: float
    issues: List[SecurityIssue]
    summary: str
    code_hash: str
    analysis_timestamp: str
    secrets_found: bool = False
    llm_risks_detected: bool = False

def run_bandit_analysis(code: str) -> Dict[str, Any]:
    """Run Bandit static analysis on the provided code"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        result = subprocess.run([
            'bandit', '-f', 'json', temp_file
        ], capture_output=True, text=True, timeout=30)
        
        os.unlink(temp_file)
        
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            return {"errors": [result.stderr], "results": []}
            
    except Exception as e:
        return {"error": str(e), "results": []}

def is_safe_pattern(code: str, category: str) -> bool:
    """Check if code contains safe patterns that should override vulnerability detection"""
    safe_indicators = {
        "sql_injection": SAFE_PATTERNS["safe_sql_indicators"],
        "command_injection": SAFE_PATTERNS["safe_command_indicators"],
        "dangerous_python": SAFE_PATTERNS["safe_command_indicators"],
        "java_command_injection": SAFE_PATTERNS["safe_command_indicators"],
    }
    
    if category in safe_indicators:
        for pattern in safe_indicators[category]:
            if re.search(pattern, code, re.IGNORECASE):
                return True
    return False

def detect_secrets(code: str) -> List[SecurityIssue]:
    """Enhanced secrets detection"""
    issues = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for category, patterns in SECRETS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(SecurityIssue(
                        type=f"secret_{category}",
                        pattern=pattern,
                        line_number=line_num,
                        severity="CRITICAL",
                        description=f"Hardcoded {category.replace('_', ' ')} detected",
                        remediation="Remove immediately and rotate keys. Use environment variables.",
                        code_snippet=line.strip()[:50] + " [REDACTED]"  # Don't expose secrets
                    ))
    return issues

def detect_llm_risks(code: str) -> List[SecurityIssue]:
    """Detect LLM-specific security risks"""
    issues = []
    lines = code.split('\n')
    
    for line_num, line in enumerate(lines, 1):
        for category, patterns in LLM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(SecurityIssue(
                        type=f"llm_{category}",
                        pattern=pattern,
                        line_number=line_num,
                        severity="HIGH",
                        description=f"LLM {category.replace('_', ' ')} risk detected",
                        remediation="Sanitize LLM inputs/outputs, implement guardrails",
                        code_snippet=line.strip()[:100]
                    ))
    return issues

def ast_analysis(code: str) -> List[SecurityIssue]:
    """Basic AST analysis for Python code"""
    issues = []
    
    try:
        tree = ast.parse(code)
        
        for node in ast.walk(tree):
            # Detect unsafe function calls with user input
            if isinstance(node, ast.Call):
                if (isinstance(node.func, ast.Name) and 
                    node.func.id in ['eval', 'exec', 'compile']):
                    
                    issues.append(SecurityIssue(
                        type="ast_unsafe_exec",
                        pattern="ast_analysis",
                        line_number=node.lineno,
                        severity="CRITICAL",
                        description="Unsafe code execution detected via AST analysis",
                        remediation="Avoid eval/exec with dynamic content",
                        code_snippet=code.split('\n')[node.lineno-1][:100]
                    ))
                    
    except SyntaxError:
        # Code might not be valid Python, skip AST analysis
        pass
        
    return issues

def regex_scan(code: str, is_llm_output: bool = False) -> List[SecurityIssue]:
    """Perform comprehensive security scanning"""
    issues = []
    
    # Existing regex scanning
    lines = code.split('\n')
    all_patterns = {**SECURITY_PATTERNS, **MULTI_LANGUAGE_PATTERNS, **ENHANCED_PATTERNS}
    
    for line_num, line in enumerate(lines, 1):
        for category, patterns in all_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    if is_safe_pattern(line, category):
                        continue
                    issue = create_issue_from_pattern(category, pattern, line_num, line)
                    if issue:
                        issues.append(issue)
    
    # ADD: Enhanced detection
    issues += detect_secrets(code)
    
    if is_llm_output:
        issues += detect_llm_risks(code)
    
    # ADD: AST analysis for Python
    if any(ext in code for ext in ['.py', 'import ', 'def ']):
        issues += ast_analysis(code)
    
    return issues

def create_issue_from_pattern(category: str, pattern: str, line_num: int, line: str) -> Optional[SecurityIssue]:
    """Create SecurityIssue object from detected pattern"""
    severity_map = {
        "sql_injection": "CRITICAL",
        "command_injection": "CRITICAL",
        "dangerous_commands": "CRITICAL",
        "file_operations": "HIGH",
        "deserialization": "CRITICAL",
        "hardcoded_secrets": "CRITICAL",
        "suspicious_urls": "MEDIUM",
        "java_deserialization": "CRITICAL",
        "java_command_injection": "CRITICAL",
        "javascript_injection": "HIGH",
        "c_cpp_memory_issues": "HIGH",
        "file_upload_risks": "HIGH",
        "path_traversal": "HIGH",
        "insecure_cors": "HIGH",
        "xss_vulnerabilities": "HIGH",
        "unsafe_file_operations": "HIGH",
        "insecure_authentication": "CRITICAL",
        "information_disclosure": "HIGH"
    }
    
    description_map = {
        "sql_injection": "SQL injection vulnerability - can lead to data theft",
        "command_injection": "Command injection - can execute arbitrary system commands",
        "dangerous_commands": "Dangerous system command - can damage system or data",
        "file_operations": "Dangerous file operation - can modify or delete files",
        "deserialization": "Unsafe deserialization - can lead to remote code execution",
        "hardcoded_secrets": "Hardcoded credentials or API keys - immediate revocation required",
        "suspicious_urls": "Suspicious URL or network operation",
        "java_deserialization": "Java deserialization vulnerability - remote code execution risk",
        "java_command_injection": "Java command injection - can execute system commands",
        "javascript_injection": "JavaScript injection - XSS and code execution risk",
        "c_cpp_memory_issues": "C/C++ memory issue - buffer overflow potential",
        "file_upload_risks": "Unsafe file upload - potential path traversal or arbitrary file upload",
        "path_traversal": "Path traversal vulnerability - can access arbitrary files",
        "insecure_cors": "Insecure CORS configuration - allows requests from any origin",
        "xss_vulnerabilities": "Cross-site scripting vulnerability - can execute arbitrary JavaScript",
        "unsafe_file_operations": "Unsafe file operations with user input",
        "insecure_authentication": "Insecure client-side authentication storage - credentials exposed",
        "information_disclosure": "Information disclosure - sensitive data logged or exposed"
    }
    
    remediation_map = {
        "sql_injection": "Use parameterized queries or ORM with input validation",
        "command_injection": "Avoid user input in system commands, use subprocess safely",
        "dangerous_commands": "Remove dangerous commands, use safe alternatives with validation",
        "file_operations": "Validate file paths, use secure permissions, restrict operations",
        "deserialization": "Avoid pickle with untrusted data, use JSON with validation",
        "hardcoded_secrets": "Remove immediately and rotate keys. Use environment variables.",
        "suspicious_urls": "Validate and sanitize all URLs and network requests",
        "java_deserialization": "Use safe serialization libraries, validate input, avoid ObjectInputStream",
        "java_command_injection": "Validate and sanitize all inputs to Runtime.exec(), use ProcessBuilder safely",
        "javascript_injection": "Use safe DOM manipulation, avoid eval() with user input, implement CSP",
        "c_cpp_memory_issues": "Use safe string functions, validate buffer sizes, use bounds checking",
        "file_upload_risks": "Validate filenames, use safe file operations, restrict upload directories",
        "path_traversal": "Canonicalize paths, restrict to safe directories, validate input",
        "insecure_cors": "Restrict CORS to specific origins, avoid wildcard for authenticated endpoints",
        "xss_vulnerabilities": "Use textContent instead of innerHTML, implement output encoding, use CSP",
        "unsafe_file_operations": "Validate file paths, use safe file APIs, restrict permissions",
        "insecure_authentication": "Use secure HTTP-only cookies, avoid client-side secret storage",
        "information_disclosure": "Avoid logging sensitive data, implement proper logging filters"
    }
    
    if category not in severity_map:
        return None
        
    return SecurityIssue(
        type=category,
        pattern=pattern,
        line_number=line_num,
        severity=severity_map[category],
        description=description_map.get(category, "Security vulnerability detected"),
        remediation=remediation_map.get(category, "Review and fix the security issue"),
        code_snippet=line.strip()[:100]
    )

def calculate_risk_score(issues: List[SecurityIssue]) -> tuple[str, float]:
    """Calculate overall risk score and level"""
    if not issues:
        return "LOW", 0.0
    
    severity_weights = {"LOW": 1, "MEDIUM": 3, "HIGH": 5, "CRITICAL": 10}
    total_weight = sum(severity_weights[issue.severity] for issue in issues)
    max_possible = len(issues) * 10
    score = (total_weight / max_possible) * 100 if max_possible > 0 else 0
    
    if score >= 80:
        return "CRITICAL", score
    elif score >= 60:
        return "HIGH", score
    elif score >= 30:
        return "MEDIUM", score
    else:
        return "LOW", score

def generate_code_hash(code: str) -> str:
    """Generate SHA256 hash of the code for tracking"""
    return hashlib.sha256(code.encode()).hexdigest()

@app.get("/")
async def root():
    return {"message": "Advanced Code Security Scanner API - Enhanced Detection"}

@app.post("/analyze", response_model=AnalysisResult)
async def analyze_code(request: CodeAnalysisRequest):
    """Analyze code for security vulnerabilities with reduced false positives"""
    try:
        if not request.code.strip():
            raise HTTPException(status_code=400, detail="Code cannot be empty")
        
        if len(request.code) > 100000:
            raise HTTPException(status_code=400, detail="Code too large")
        
        # Run all security analyses
        regex_issues = regex_scan(request.code, request.is_llm_output)
        bandit_report = run_bandit_analysis(request.code)
        secrets_issues = detect_secrets(request.code)
        
        # Convert Bandit issues
        bandit_issues = []
        if bandit_report and "results" in bandit_report:
            for issue in bandit_report["results"]:
                bandit_issues.append(SecurityIssue(
                    type="bandit",
                    pattern=issue.get("test_id", ""),
                    line_number=issue.get("line_number", 0),
                    severity=issue.get("issue_severity", "MEDIUM").upper(),
                    description=issue.get("issue_text", ""),
                    remediation=issue.get("more_info", "See Bandit documentation"),
                    code_snippet=issue.get("code", "")[:100]
                ))
        
        # Combine all issues
        all_issues = regex_issues + bandit_issues + secrets_issues
        
        # ADD: Enhanced summary info
        secrets_found = any("secret_" in issue.type for issue in all_issues)
        llm_risks_detected = any("llm_" in issue.type for issue in all_issues)
        
        # Calculate overall risk
        overall_risk, risk_score = calculate_risk_score(all_issues)
        
        summary = f"Found {len(all_issues)} security issues. "
        if secrets_found:
            summary += "SECRETS DETECTED! "
        if llm_risks_detected:
            summary += "LLM risks found. "
        summary += f"Risk level: {overall_risk}"
        
        return AnalysisResult(
            overall_risk=overall_risk,
            score=risk_score,
            issues=all_issues,
            summary=summary,
            code_hash=generate_code_hash(request.code),
            analysis_timestamp=datetime.now().isoformat(),
            secrets_found=secrets_found,
            llm_risks_detected=llm_risks_detected
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze-file")
async def analyze_code_file(file: UploadFile = File(...)):
    """Analyze code from uploaded file"""
    try:
        content = await file.read()
        code = content.decode('utf-8')
        
        request = CodeAnalysisRequest(code=code)
        return await analyze_code(request)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File analysis failed: {str(e)}")

@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "6.0.0"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)