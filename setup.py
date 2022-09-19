from setuptools import setup

setup(
    name="smallcloud",
    py_modules=["smallcloud"],
    packages=["smallcloud"],
    version="0.3.0",
    url="https://github.com/smallcloudai/smallcloud",
    summary="Command line tool to access smallcloud.ai services",
    description="Run your GPU-intensive tasks using this command line tool / Python library",
    license='GNU GPLv3',
    install_requires=[
        "termcolor",
        "pandas",
    ],
    author="Small Magellanic Cloud AI Ltd.",
    author_email="cli-tool@smallcloud.tech",
    entry_points={
        "console_scripts": ["s = smallcloud.__main__:main"],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Environment :: Console",
        "Operating System :: OS Independent",
    ]
)
