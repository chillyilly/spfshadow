from setuptools import setup, find_packages

setup(
    name="spfshadow-advanced",
    version="1.0.0",
    description="Comprehensive subdomain and SPF shadowing tool",
    author="chill",
    author_email="chill[@]dirtywhitehat.net",
    packages=find_packages(),
    install_requires=["requests", "dnspython", "beautifulsoup4"],
    entry_points={
        "console_scripts": ["spfshadow-advanced=spfshadow_advanced.main:main"]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)
