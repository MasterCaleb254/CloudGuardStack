from setuptools import setup, find_packages

setup(
    name="cloud-guard-stack",
    version="0.1.0",
    packages=find_packages(include=['scanners', 'scanners.*']),  # Updated to include submodules
    install_requires=[
        'boto3>=1.28.0',
        'pandas>=1.3.0',
    ],
)