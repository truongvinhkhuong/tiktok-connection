"""
Setup script cho TikTok Shop OAuth Callback Application
"""

from setuptools import setup, find_packages

setup(
    name="tiktok-oauth-callback",
    version="1.0.0",
    description="TikTok Shop OAuth Callback Application với đầy đủ tính năng bảo mật",
    author="TikTok Shop Integration Team",
    author_email="admin@truongvinhkhuong.io.vn",
    url="https://github.com/truongvinhkhuong/tiktok-connection",
    packages=find_packages(),
    install_requires=[
        "Flask>=2.3.3",
        "requests>=2.31.0", 
        "Werkzeug>=2.3.7",
        "python-dotenv>=1.0.0",
        "gunicorn>=21.2.0"
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0"
        ],
        "production": [
            "psycopg2-binary>=2.9.7",  # PostgreSQL support
            "redis>=4.6.0"  # Redis for session storage
        ]
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9", 
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Framework :: Flask",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        "Topic :: Software Development :: Libraries :: Application Frameworks"
    ],
    keywords="tiktok oauth flask callback api integration",
    entry_points={
        "console_scripts": [
            "tiktok-oauth=run:main"
        ]
    }
)