from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network_scanner",
    version="0.1.0",
    author="Adrian",
    author_email="adrian@example.com",
    description="A modular, stealthy network scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/network-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires=">=3.7",
    install_requires=[
        "scapy>=2.4.5",
        "python-nmap>=0.7.1",
        "pyyaml>=6.0",
        "click>=8.0.0",
        "rich>=12.0.0",
        "python-dotenv>=0.19.0",
        "fastapi>=0.95.0",
        "uvicorn>=0.21.0",
        "flask>=2.0.0",
        "requests>=2.25.0",
        "flask-cors>=3.0.10",
    ],
    entry_points={
        "console_scripts": [
            "netscanner=network_scanner.frontend.cli.main:main",
            "netscanner-api=network_scanner.backend.api.main:main",
            "netscanner-web=network_scanner.frontend.web.app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "network_scanner.frontend.web": ["templates/*"],
    },
) 