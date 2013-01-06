# How to contribute to Peace of Mind

Peace of Mind uses Buildout to facilitate development which includes testing.

* Fork Peace of Mind
* Check out your fork: `git clone git@github.com:<<YOU>>/python-peace-of-mind.git`
* Get into the directory: `cd python-peace-of-mind`
* Create a topic branch: `git checkout -b my_branch`
* Push to your branch: `git push origin my_branch``
* Make your awesome commits and write tests and documentation as outlined below
* Create a Pull Request from your branch

-------------

The first line below will get buildout boostrapped and the second will install
all the dependencies of the library and get everything ready.

* `python buildout.py`
* `./bin/buildout`

To run tests:

* `./bin/nosetests`

To open a Python shell with the library loaded:

* `./bin/python`

To generate documentation:

* `./bin/sphinx-build -b html ./docs ./docs/_build/`
