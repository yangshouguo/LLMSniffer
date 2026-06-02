from setuptools import setup, find_packages

setup(
    name="llm-sniffer",
    version="0.1.0",
    description="Capture and display LLM API traffic like wireshark for LLMs",
    author="LLM Sniffer",
    packages=find_packages(),
    install_requires=[
        "aiohttp>=3.9.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "llm-sniffer=llm_sniffer.main:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
