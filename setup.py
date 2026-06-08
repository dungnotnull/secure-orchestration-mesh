"""
Setup configuration for the secure-orchestration-mesh SDK package.

Installable via: pip install secure-orchestration-mesh-sdk
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="secure-orchestration-mesh-sdk",
    version="0.1.0",
    description="Zero-Trust Security Protocol for AI Orchestrator-SubAgent Communication",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="secure-orchestration-mesh contributors",
    url="https://github.com/secure-orchestration-mesh/secure-orchestration-mesh",
    packages=find_packages(
        include=[
            "proto", "proto.*",
            "agent_sdk", "agent_sdk.*",
            "orchestrator", "orchestrator.*",
            "anomaly", "anomaly.*",
            "translator", "translator.*",
            "llm", "llm.*",
            "self_update", "self_update.*",
        ]
    ),
    python_requires=">=3.11",
    install_requires=[
        "grpcio>=1.64.0",
        "grpcio-tools>=1.64.0",
        "protobuf>=4.25.0",
        "cryptography>=42.0.0",
        "python-jose[cryptography]>=3.3.0",
        "scikit-learn>=1.5.0",
        "torch>=2.3.0",
        "transformers>=4.41.0",
        "httpx>=0.27.0",
        "anthropic>=0.28.0",
        "openai>=1.30.0",
        "ollama>=0.2.0",
        "pydantic>=2.7.0",
        "pyyaml>=6.0",
        "opentelemetry-sdk>=1.24.0",
        "websockets>=12.0",
        "aiosqlite>=0.20.0",
        "numpy>=1.26.0",
        "rich>=13.7.0",
        "apscheduler>=3.10.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.2.0",
            "pytest-asyncio>=0.23.0",
            "pytest-cov>=5.0.0",
            "black>=24.0.0",
            "ruff>=0.4.0",
        ],
        "crewai": ["crewai>=0.28.0"],
        "langgraph": ["langgraph>=0.2.0", "langchain>=0.2.0"],
        "all": [
            "crewai>=0.28.0",
            "langgraph>=0.2.0",
            "langchain>=0.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "som-orchestrator=orchestrator.main:main",
            "som-agent=agent_sdk.main:main",
            "som-generate-logs=scripts.synthetic_log_generator:main",
            "som-generate-attacks=scripts.attack_simulator:main",
            "som-self-update=self_update.crawl4ai_pipeline:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    keywords="ai-security, zero-trust, multi-agent, grpc, anomaly-detection, agent-orchestration",
)
