from setuptools import setup, find_packages

setup(
    name="vulscan",
    version="0.1.0",
    description="Simple vulnerability scanner",
    author="Gringobin",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "colorama",
    ],
    entry_points={
        "console_scripts": [
            "vulscan=vulscan.main:main"
        ]
    },
)