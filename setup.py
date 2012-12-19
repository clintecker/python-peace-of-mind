import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "python-peace-of-mind",
    version='0.1',
    url = 'http://github.com/clintecker/python-peace-of-mind',
    license = 'BSD',
    description = "A library for letting you sleep at night.",
    long_description = read('README.md'),

    author = 'Clint Ecker',
    author_email = 'me@clintecker.com',

    packages = find_packages('src'),
    package_dir = {'': 'src'},

    install_requires = ['setuptools', 'spam-blocklists', 'whois', 'requests'],

    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
    ]
)
