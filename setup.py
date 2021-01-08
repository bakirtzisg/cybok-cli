# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

if __name__ == "__main__":
    setup(
        name='cybok',
        version='0.1.0',
        description='Automated model-based vulnerability assessment',
        author='Georgios Bakirtzis',
        author_email='bakirtzisg@ieee.org',
        platforms='ALL',
        url='https://github.com/bakirtzisg/cybok',
        python_requires='>=3.6.4',
        packages=['cybok'],
        long_description=open('README.org').read(),
        install_requires=[
            "beautifulsoup4==4.6.0",
            "lxml==4.6.2",
            "networkx==2.1",
            "whoosh==2.7.4",
            "requests==2.20.0",
            "sty==1.0.0b6",
            "matplotlib==2.2.2",
            "pygraphviz==1.3.1",
        ],
        classifiers=[
            'Environment :: Console',
            'Programming Language :: Python :: 3.6',
        ]
)
