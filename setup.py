from setuptools import setup, find_packages

setup(
    name="blockcrypt_core",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "blockcrypt_cli=blockcrypt_core.driver:main",
        ]
    }
)