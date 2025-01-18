
===============
Get started
===============

To get started on hosting your own `pufferblow <https://github.com/PufferBlow/pufferblow>`__ server, you will need the following:

* Linux VPS
* PostgreSQL

Setup a Linux VPS
=================

Numerous affordable VPS services are available, offering reliable Linux VPS solutions. Among the options that we recommend are:

* `Oracle's Free tier <https://www.oracle.com/cloud/free>`_
* `Contabo <https://contabo.com/en/>`_

Setup PostgreSQL
================

Head over `PostgreSQL's download page <https://www.postgresql.org/download/>`_ and follow the instructions based on your distro.

Install pufferblow
=====================

Installing **pufferblow** is very straight forward all you need to do is:

* Install via Git:

.. code-block:: bash

    pip install git+https://github.com/pufferblow/pufferblow.git

* Build from source:

.. code-block:: bash

    git clone https://github.com/pufferblow/pufferblow.git --depth=1
    cd pufferblow
    pip install -e .

Setup pufferblow
================

pufferblow has a command called setup that enables you to set it up, all you need to do is run the following:

.. code-block:: bash

    pufferblow setup

if it detects that a config file is already present, the following will be outputed:

.. code-block::

    A config file already exists. Do you want to continue? [y/n]:

but normaly it will ask you for your postgreSQL database name, the default is postgres:

.. code-block::

    PostgreSQL database name (postgres):

then it will ask you about the database's username, password, host and port:

.. code-block::

    PostgreSQL database username:
    PostgreSQL database password:
    PostgreSQL database host:
    PostgreSQL database name port:

after that it will ask you about some light info on your server, like the server name, description, welcome message:

.. code-block::

    Enter your server's name:
    Enter your server's description:
    Enter your server's welcome message for new members:

and lastly the username, password for the admin user:

.. code-block::

    Enter your owner account username:
    Enter your owner account password:

.. note::

    Don't panic when typing in a password; it will not be shown by design.

Start your pufferblow server
============================

Now you can start your pufferblow server with the following command:

.. code-block:: bash

    pufferblow serve
