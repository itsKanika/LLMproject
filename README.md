<h1 align="center" id="title">LLM CODE SECURITY CHECKER</h1>

<p align="center"><img src="https://drive.google.com/file/d/1cSKbeP_kKi29cPsvPk2HrXP2TdecGXqo/view?usp=drive_link" alt="project-image"></p>

<p id="description">The LLM Code Authenticity &amp; Security Analyzer is designed to detect AI-generated code patterns and potential security vulnerabilities in source code. It leverages 50+ regex rules static analysis and Bandit integration without relying on machine learning. The tool performs pattern-based scanning AST parsing and vulnerability assessment to identify suspicious coding behaviors. It checks for AI code indicators such as generic names and placeholder comments security risks like hardcoded credentials SQL/command injection and insecure file operations as well as code quality issues including broad or empty exception blocks and leftover debug code. The analyzer generates risk scores along with detailed JSON reports containing line-by-line insights and is accessible via a FastAPI REST API for easy code submission and integration. It is ideal for developers educators code reviewers and security teams to verify code authenticity detect vulnerabilities and improve overall code quality.</p>

<h2>🚀 Demo</h2>

[https://www.youtube.com/watch?v=HYjaUiqGHv0&t=3s](https://www.youtube.com/watch?v=HYjaUiqGHv0&t=3s)

<h2>Project Screenshots:</h2>

<img src="https://drive.google.com/file/d/1Et_WcE0_yh8e2RoIHkNcOU0Je54HONuM/view?usp=drive_link" alt="project-screenshot" width="900" px="" height="600">

<img src="https://drive.google.com/file/d/1Nmtg4NYoPOPRVaSxhEoL6OyCEJ_2IhyQ/view?usp=drive_link" alt="project-screenshot" width="900" px="" height="600">

<img src="https://drive.google.com/file/d/1-WDK4H74xokvNQTgiPamCKSm_HpXuqYn/view?usp=drive_link" alt="project-screenshot" width="900" px="" height="600">

  
  
<h2>🧐 Features</h2>

Here're some of the project's best features:

*   Detects AI-generated code patterns with 50+ regex rules
*   Scans for security vulnerabilities using Bandit
*   Performs AST-based code structure analysis
*   Generates risk scores for security & authenticity
*   Provides detailed JSON reports with line-by-line insights
*   Exposes a REST API for easy integration

<h2>🛠️ Installation Steps:</h2>

<p>1. Create &amp; activate a virtual environment (Python 3.10+ recommended)</p>

```
python -m venv venv source venv/bin/activate      # Linux / macOS venv\Scripts\activate         # Windows
```

<p>2. Install dependencies</p>

```
pip install -r requirements.txt
```

<p>3. Start the FastAPI server</p>

```
uvicorn main:app --reload
```

<p>4. For frontend</p>

```
npm run dev
```

  
  
<h2>💻 Built with</h2>

Technologies used in the project:

*   FastAPI
*   Bandit
*   Python 3.10+
*   Regex Pattern Matching
*   RESTful API
*   React.js
