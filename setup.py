"""A setuptools based setup module.
See:
https://packaging.python.org/guides/distributing-packages-using-setuptools/
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
import pathlib

here = pathlib.Path(__file__).parent.resolve()

# Get the long description from the README file
long_description = (here / "README.md").read_text(encoding="utf-8")

# Arguments marked as "Required" below must be included for upload to PyPI.
# Fields marked as "Optional" may be commented out.

setup(
    name="charms.osm",
    version="0.0.1",
    description="A library for improving the development experience of Charms in OSM",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/charmed-osm/charms.osm",
    author="Canonical",
    author_email="david.garcia@canonical.com",
    keywords="charm, osm, development",
    install_requires=[
        "ops",
        "packaging",
    ],
    project_urls={
        "Bug Reports": "https://github.com/charmed-osm/charms.osm/issues",
        "Source": "https://github.com/charmed-osm/charms.osm",
    },
    packages=find_packages(include=("charms", "charms.*", "charms.osm.*")),
    python_requires=">=3.5",
)
