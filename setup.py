from setuptools import setup, find_packages


setup(
    name='spiral',
    description='elliptic-curve-protected protocol implementations for twisted',
    author='Aaron Gallagher',
    author_email='_@habnab.it',
    url='https://github.com/habnabit/spiral',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
    ],
    license='ISC',

    setup_requires=['vcversioner'],
    vcversioner={},
    install_requires=[
        'Twisted',
        'interval',
        'pynacl',
    ],
    entry_points={
        'console_scripts': [
            'curvecpmserver = spiral.scripts.curvecpmserver:main',
            'curvecpmclient = spiral.scripts.curvecpmclient:main',
        ],
    },

    packages=find_packages(),
    zip_safe=False,
)
