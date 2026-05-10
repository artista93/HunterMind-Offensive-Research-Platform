#!/usr/bin/env python3
"""Setup script for HunterMind platform."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt", "r", encoding="utf-8") as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith("#")]

setup(
    name="huntermind",
    version="1.0.0",
    author="HunterMind Team",
    author_email="artistajaafari@gmail.com",
    description="Autonomous Offensive Security Intelligence Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/akkalighter/HunterMind_Offensive_Research_Platform",
    packages=find_packages(exclude=["tests", "docs", "datasets", "models"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "gpu": [
            "tensorflow-gpu>=2.13.0",
            "torch>=2.0.0 --index-url https://download.pytorch.org/whl/cu118",
            "faiss-gpu>=1.7.4",
        ],
        "research": [
            "jupyter>=1.0.0",
            "mlflow>=2.4.0",
            "optuna>=3.2.0",
            "plotly>=5.15.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "ruff>=0.0.285",
            "mypy>=1.4.0",
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
