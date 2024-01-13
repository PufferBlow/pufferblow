==============================
Introduction to pufferblow-api
==============================

Introduction
============

The `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ is the official open-source server for `PufferBlow <https://github.com/PufferBlow/pufferblow>`__. Using it you can host your own server and create a community for you, your friends, and potentially others to join and spend wonderful times together. One of the key strengths of the `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ is its robust security measures. Being open-source and free to use, it ensures your privacy as it implements advanced encryption algorithms such as Blowfish and bcrypt for data hashing and encryption, making the `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ a secure choice for hosting your own server.
Unlike many other chat services that offer little control to the server owner, such as Discord and Guilded, `PufferBlow <https://github.com/PufferBlow/pufferblow>`__ stands apart. With `PufferBlow <https://github.com/PufferBlow/pufferblow>`__, you have the ability to host your own server using `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ and customize it according to your preferences.

The ideology of pufferblow-api
==============================

This service enables users to host their own servers or instances while maintaining a consistent user experience across all these servers. Furthermore, users only need to create a single account on one server, which will be synchronized across all instances (aka fediverse network).

.. note::

   As of version **v0.0.1-beta**, the `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ does not yet support the Fediverse. However, this feature is planned for future releases. The primary reason for creating PufferBlow was to develop a Fediverse-compatible Discord-like chat service, which aligns with the ethos of the Fediverse itself.

Prerequisites
=============

To start hosting your server, you will first need a couple things:

* A **Linux VPS**, it can be any Linux distro that you want as long as it meets the following requirements:
 
 * At least 2 CPU cores.

 * 1 to 2 GB of RAM.
 
 * High network bandwidth.

.. note::

  you won't need a lot of storage to host `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__, but if you are going to also host your own instance of `supabase <https://supabase.com/>`__ than it is recommended to have at least **50GB of storage or higher**.

* `supabase <https://supabase.com/>`__ is an open-source alternative to Firebase. You have the option to either self-host it or use their free plan available at https://supabase.com. However, it's recommended not to self-host unless your server has a large number of members. If your server is expected to grow significantly, then self-hosting becomes the optimal solution. In such cases, you may also need to consider upgrading your VPS hardware to accommodate the increased load.

Dependencies
============

These are mostly python libs and dependencies that are used by pufferblow-api:

.. _FastAPI: https://fastapi.tiangolo.com/
.. _Typer: https://typer.tiangolo.com/
.. _Rich: https://rich.readthedocs.io/en/latest/
.. _Uvicorn: https://www.uvicorn.org/
.. _PyYAML: https://pyyaml.org/wiki/PyYAMLDocumentation
.. _PyCryptodome: https://www.pycryptodome.org/en/latest/
.. _bcrypt: https://pypi.org/project/bcrypt/
.. _Loguru: https://loguru.readthedocs.io/en/stable/
.. _pytz: http://pythonhosted.org/pytz/
.. _psycopg2-binary: https://www.psycopg.org/docs/
.. _pytest: https://docs.pytest.org/en/latest/
.. _SQLAlchemy: https://www.sqlalchemy.org/
.. _Websockets: https://websockets.readthedocs.io/en/stable/
.. _HTTPX: https://www.python-httpx.org/

* `FastAPI <FastAPI_>`_: FastAPI is a modern, fast (high-performance), web framework for building APIs with Python 3.6+ based on standard Python type hints.
* `Typer <Typer_>`_: Typer is a library for building command line interface (CLI) applications, with support for argument parsing, validation, help messages, and more.
* `Rich <Rich_>`_: Rich is a Python library for rendering rich text and beautiful formatting to the terminal.
* `Uvicorn <Uvicorn_>`_: Uvicorn is a lightning-fast ASGI server implementation, using uvloop and httptools.
* `PyYAML <PyYAML_>`_: PyYAML is a YAML parser and emitter for Python.
* `PyCryptodome <PyCryptodome_>`_: PyCryptodome is a self-contained Python package of low-level cryptographic primitives.
* `bcrypt <bcrypt_>`_: bcrypt is a password hashing function designed by Niels Provos and David Mazières.
* `Loguru <Loguru_>`_: Loguru is a library which aims to bring enjoyable logging in Python.
* `pytz <pytz_>`_: pytz brings the Olson tz database into Python.
* `psycopg2-binary <psycopg2-binary_>`_: psycopg2-binary is a stand-alone package that includes the PostgreSQL binary libraries.
* `pytest <pytest_>`_: pytest is a mature full-featured Python testing tool that helps you write better programs.
* `SQLAlchemy <SQLAlchemy_>`_: SQLAlchemy is the Python SQL toolkit and Object-Relational Mapping (ORM) system.
* `Websockets <Websockets_>`_: Websockets is a library for building WebSocket servers and clients in Python.
* `HTTPX <HTTPX_>`_: HTTPX is a fully featured HTTP client for Python 3, which provides sync and async APIs, and support for both HTTP/1.1 and HTTP/2.

for the documentation, we used the `sphinx <https://www.sphinx-doc.org/en/master/>`__ document generator:

.. _Sphinx: https://www.sphinx-doc.org/en/master/
.. _SphinxBookTheme: https://github.com/executablebooks/sphinx-book-theme
.. _SphinxAutobuild: https://pypi.org/project/sphinx-autobuild/
.. _SphinxFavicon: https://pypi.org/project/sphinx-favicon/

* `Sphinx <Sphinx_>`_: Sphinx is a tool that makes it easy to create intelligent and beautiful documentation.
* `Sphinx Book Theme <SphinxBookTheme_>`_: The Sphinx Book Theme is a theme for Sphinx that is designed to look good for books and documentation.
* `Sphinx Autobuild <SphinxAutobuild_>`_: Sphinx Autobuild is a tool that automatically rebuilds your Sphinx documentation whenever changes are detected.
* `Sphinx Favicon <SphinxFavicon_>`_: Sphinx Favicon is an extension for Sphinx that adds support for favicons in your documentation.
