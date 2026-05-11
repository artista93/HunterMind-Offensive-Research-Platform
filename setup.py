#!/usr/bin/env python3
"""Setup script for HunterMind platform."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="huntermind",
    version="1.0.0",
    author="HunterMind Team",
    author_email="artistajaafari@gmail.com",
    description="Autonomous Offensive Security Intelligence Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/akkalighter/HunterMind_Offensive_Research_Platform",
    packages=find_packages(
        include=[
            "offensive", "offensive.*",
            "agents", "agents.*",
            "cognition", "cognition.*",
            "learning", "learning.*",
            "orchestration", "orchestration.*",
            "interfaces", "interfaces.*",
            "infrastructure", "infrastructure.*",
            "storage", "storage.*",
            "telemetry", "telemetry.*",
            "schemas", "schemas.*"
        ],
        exclude=["tests", "tests.*", "docs", "docs.*", "datasets", "models", "scripts"]
    ),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.8.0",
        "httpx>=0.24.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "websockets>=12.0",
        "playwright>=1.40.0",
        "beautifulsoup4>=4.12.0",
        "numpy>=1.24.0",
        "pydantic>=2.0.0",
        "pyyaml>=6.0",
        "python-dotenv>=1.0.0",
        "psutil>=5.9.0",
    ],
    extras_require={
        "gpu": [
            "tensorflow>=2.13.0",
            "torch>=2.0.0",
        ],
        "research": [
            "jupyter>=1.0.0",
            "matplotlib>=3.7.0",
            "pandas>=2.0.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "ruff>=0.0.285",
        ],
    },
    entry_points={
        "console_scripts": [
            "huntermind=cli:main",
            "huntermind-api=interfaces.api.fastapi_server:main",
            "huntermind-dashboard=interfaces.dashboard.dashboard_server:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
