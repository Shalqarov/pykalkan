from setuptools import setup, find_packages

setup(
    name="pykalkan",
    version="0.5.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
)