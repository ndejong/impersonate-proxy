# 🤖 impersonate-proxy — Agent Directory (`.agents`)

Welcome, AI Agent! This directory contains configurations, rules, contexts, specialized skills, and workflow definitions designed to help you understand the impersonate-proxy repository, make high-quality changes, and verify your implementation.

---

## 📂 Directory Structure

Here is the layout of the `.agents` folder:

```
.agents/
├── AGENTS.md                          # This file (Agent guide)
├── context/
│   └── project_context.md             # Core design principles and guidelines
├── rules/
│   ├── dev-directory.md               # Rule prohibiting reading/writing to _dev/
│   └── environment.md                 # Rule enforcing isolated, non-local .venv usage
├── skills/
│   ├── architect-review/
│   │   └── SKILL.md                   # System design & architecture review rules
│   ├── caveman/
│   │   └── SKILL.md                   # Ultra-compressed communication mode instructions
│   ├── code-reviewer/
│   │   └── SKILL.md                   # Security, performance, and best practices review rules
│   ├── karpathy-guidelines/
│   │   └── SKILL.md                   # Andrej Karpathy guidelines for senior LLM coding
│   ├── python-pro/
│   │   └── SKILL.md                   # Python 3.11+ and tool-specific guidelines (uv, ruff)
│   ├── uv-testing/
│   │   └── SKILL.md                   # Guidelines on isolated virtual env testing
│   └── vulnerability-scanner/
│       ├── SKILL.md                   # Advanced vulnerability analysis principles
│       ├── checklists.md              # OWASP top 10 security checklists
│       └── scripts/
│           └── security_scan.py       # Automated project security validation script
└── workflows/
    ├── post-implementation-verification.md  # Step-by-step verification checklist
    └── uv-commands.md                 # How to execute uv commands without local .venv leakage
```

---

## 🧩 Core Components

### 1. Context (`context/`)
* **[project_context.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/context/project_context.md)**: **CRITICAL.** Read this file before making any changes. It details:
  * **Core Stack**: Python 3.11+, setuptools, curl_cffi, cryptography, and package management with `uv`.
  * **Architectural Decisions**: In-memory CA Root generation and installation in system trust store; dynamic SSLContext server-side socket wrapper for MITM decryption; fallback to raw TCP tunnels.
  * **Coding Standards**: Synchronous socket and connection loop handling, ruff-lint checked code, and strict isolation of virtual environment.

### 2. Rules (`rules/`)
* **[dev-directory.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/rules/dev-directory.md)**: Prohibits interacting with the `_dev/` folder. The `_dev/` directory is an untracked developer scratch space and must be treated as invisible.
* **[environment.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/rules/environment.md)**: Enforces that no local `.venv` directory is created inside the repository workspace. Virtual environments and cache paths must be redirected using standard prefix environment variables.

### 3. Skills (`skills/`)
These represent specialized instructions to guide your implementation:
* **[architect-review](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/skills/architect-review/SKILL.md)**: Review system design, maintain architectural integrity, follow clean architecture practices.
* **[caveman](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/skills/caveman/SKILL.md)**: Guidelines for ultra-compressed communication, reducing token usage while retaining maximum technical accuracy.
* **[code-reviewer](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/skills/code-reviewer/SKILL.md)**: Guide for identifying security vulnerabilities, performance bottlenecks, error-handling bugs, and code styling standards.
* **[karpathy-guidelines](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/skills/karpathy-guidelines/SKILL.md)**: Guidelines for avoiding LLM-specific coding pitfalls, focusing on simplicity, making surgical edits, and defining clear goals.
* **[python-pro](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/skills/python-pro/SKILL.md)**: Best practices for Python 3.11+, clean type hints, modern formatting, and testing patterns.
* **[uv-testing](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/skills/uv-testing/SKILL.md)**: Reinforces instructions for running testing commands under isolated execution environments.
* **[vulnerability-scanner](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/skills/vulnerability-scanner/SKILL.md)**: Provides threat modeling patterns, OWASP 2025 guidelines, supply chain safety rules, and validation tools.

### 4. Workflows (`workflows/`)
* **[post-implementation-verification.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/workflows/post-implementation-verification.md)**: A step-by-step verification checklist to execute when concluding a task.
* **[uv-commands.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/workflows/uv-commands.md)**: Explains the required environment variables prefix setup to protect the codebase workspace from `.venv` folder contamination.

---

## 🛠 Standard Agent Workflow

1. **Understand Goals & Architecture**: Read the project's [README.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/README.md) and [project_context.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/context/project_context.md).
2. **Consult Rules & Skills**: Follow [dev-directory.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/rules/dev-directory.md) and [environment.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/rules/environment.md). Check corresponding skill guidelines in the `skills/` folder if you are modifying core architecture, complex Python constructs, or security-sensitive code.
3. **Execute & Test**: Make edits, and run the test suite using the isolated environment variables pattern detailed in [uv-commands.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/workflows/uv-commands.md):
   ```bash
   UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy UV_LINK_MODE=copy uv run --extra dev pytest
   ```
4. **Lint and Format**: Check code compliance and formatting using:
   ```bash
   UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy UV_LINK_MODE=copy uv run --extra dev ruff check .
   UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/impersonate-proxy UV_CACHE_DIR=/tmp/.uv-cache-impersonate-proxy UV_LINK_MODE=copy uv run --extra dev ruff check --fix .
   ```
5. **Verify**: Follow the [post-implementation-verification.md](file:///home/ndejong/cyberco/projects/impersonate-proxy/.agents/workflows/post-implementation-verification.md) steps before submitting code changes.
