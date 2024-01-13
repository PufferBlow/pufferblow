============
Introduction
============

Introduction To pufferblow-api
==============================

The `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ is the official open-source server for `PufferBlow <https://github.com/PufferBlow/pufferblow>`__. Using it you can host your own server and create a community for you, your friends, and potentially others to join and spend wonderful times together. One of the key strengths of the `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ is its robust security measures. Being open-source and free to use, it ensures your privacy as it implements advanced encryption algorithms such as Blowfish and bcrypt for data hashing and encryption, making the `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ a secure choice for hosting your own server.
Unlike many other chat services that offer little control to the server owner, such as Discord and Guilded, `PufferBlow <https://github.com/PufferBlow/pufferblow>`__ stands apart. With `PufferBlow <https://github.com/PufferBlow/pufferblow>`__, you have the ability to host your own server using `pufferblow-api <https://github.com/PufferBlow/pufferblow-api>`__ and customize it according to your preferences.

The ideology of PufferBlow
==========================

This service enables users to host their own servers or instances while maintaining a consistent user experience across all these servers. Furthermore, users only need to create a single account on one server, which will be synchronized across all instances.

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
