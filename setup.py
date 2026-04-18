from setuptools import setup

setup(
    name='basic-nostr',
    version='1.1.0',
    author="Luke Profits",
    description="An intentionally tiny Nostr library for Python: Keys, DMs, Posts, & Products.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/lukeprofits/basic-nostr",
    packages=['basic_nostr'],
    package_dir={'basic_nostr': 'src/basic_nostr'},
    install_requires=[
        'coincurve',
        'websockets',
        'bech32',
        'cryptography',
        'certifi',
    ],
    python_requires='>=3.9',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
