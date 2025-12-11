class ComprehensiveSecurityAuditor:
    def __init__(self):
        self.checklist_rules = self._load_security_checklist()
    
    def _load_security_checklist(self):
        return {
            "authentication_secrets": {
                "hardcoded_credentials": {
                    "patterns": [
                        r"(?i)apikey\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"AWS_ACCESS_KEY_ID\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"(?i)password\s*[:=]\s*['\"][^'\"]+['\"]",
                        r"AKIA[0-9A-Z]{16}",
                        r"sk-[a-zA-Z0-9]{48}"
                    ],
                    "severity": "CRITICAL",
                    "category": "Secrets in code"
                }
            },
            "injection_risks": {
                "sql_injection": {
                    "patterns": [r"SELECT.*FROM.*WHERE.*['\"]"],
                    "severity": "CRITICAL", 
                    "category": "SQL Injection"
                },
                "command_injection": {
                    "patterns": [
                        r"os\.system\s*\(",
                        r"subprocess\.run\(.*shell=True",
                        r"child_process\.exec\s*\("
                    ],
                    "severity": "CRITICAL",
                    "category": "Command Injection"
                }
            },
            "llm_specific": {
                "prompt_injection": {
                    "patterns": [
                        r"(?i)ignore previous instructions",
                        r"(?i)system prompt",
                        r"(?i)role play as"
                    ],
                    "severity": "HIGH",
                    "category": "Prompt Injection"
                },
                "unsafe_code_generation": {
                    "patterns": [
                        r"eval\s*\(",
                        r"exec\s*\(",
                        r"pickle\.loads\s*\("
                    ],
                    "severity": "HIGH", 
                    "category": "Unsafe LLM Output"
                }
            }
            # ... include all other categories from your checklist
        }