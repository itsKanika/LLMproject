# LLM CODE AUTHENTICIT CHECKER

LLM Code Security & Authenticity Analyzer
A FastAPI-based security analysis tool that detects suspicious patterns in code using 50+ curated regex patterns and integrates with Bandit for vulnerability scanning. Designed to identify AI-generated code patterns and security risks without ML models.

🚀 Features
50+ Advanced Regex Patterns: Detects suspicious code constructs often found in AI-generated code

Bandit Integration: Comprehensive security vulnerability scanning

AI Code Detection: Pattern-based identification of LLM-generated code characteristics

Risk Scoring: Combined scoring system for security and authenticity assessment

REST API: FastAPI backend with comprehensive endpoints

Code Structure Analysis: AST parsing for deeper code understanding

Detailed Reporting: JSON reports with line-by-line analysis

📋 Pattern Categories

1. AI Code Indicators
Generic variable/function names

Placeholder comments

Overly verbose error handling

Unnecessary imports

Repeated patterns

2. Security Vulnerabilities
Hardcoded credentials

SQL injection patterns

Command injection risks

Insecure deserialization

File operation risks

3. Code Quality Issues
Empty exception blocks

Broad exception handling

Debug code left in place

Incomplete implementations

