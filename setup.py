from setuptools import setup, find_packages

setup(
    name="pykalkan",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
)
