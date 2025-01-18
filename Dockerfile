# Global variables
ARG MEMCACHED_URL="https://www.memcached.org/files/memcached-1.6.29.tar.gz"
ARG MEMCACHED_TAR_FILE="memcached-1.6.29.tar.gz"
ARG MEMCACHED_FOLDER="memcached-1.6.29"

# Installing python 3.11
FROM python:3.11

RUN apt-get update -y \
  &&  apt-get upgrade -y

# Installing dependencies packages
RUN apt-get install libevent-dev -y # Needed by memcached


# Installing pufferblow
RUN pip install git+https://github.com/PufferBlow/pufferblow.git


WORKDIR "/home"

# Installing memcached
RUN wget https://www.memcached.org/files/memcached-1.6.29.tar.gz  \
  && tar -zxvf memcached-1.6.29.tar.gz                            \
  && cd memcached-1.6.29                                          \
  && ./configure                                                  \
  && make                                                         \
  && make install                                                 \

