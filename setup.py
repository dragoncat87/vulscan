"""Setup configuration for vulscan."""

from setuptools import find_packages, setup


setup(
    name="vulscan",
    version="0.1.0",
    description="Security and compliance scanner CLI skeleton.",
    packages=find_packages(),
    install_requires=[
        "click",
        "gitpython",
        "requests",
        "rich",
        "anthropic",
    ],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "vulscan=vulscan.cli:main",
        ],
    },
)
