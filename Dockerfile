################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Main Dockerfile for PoC.                                                     #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-08-27T13:37:42+02:00                                     #
# Date Created:  2023-08-27T09:23:15+02:00                                     #
# ---------------------------------------------------------------------------- #
# Hint: Check your Dockerfile at https://www.fromlatest.io/                    #
################################################################################


## -----------------------------------------------------------------------------
## --- preamble ----------------------------------------------------------------
## -----------------------------------------------------------------------------

## --- global arguments --------------------------------------------------------


## --- set base image(s) -------------------------------------------------------

FROM ubuntu:22.04 AS base

## --- metadata ----------------------------------------------------------------

LABEL org.opencontainers.image.authors="michael.eckel@sit.fraunhofer.de"

## --- image specific arguments ------------------------------------------------

ARG user=bob
ARG uid=1000
ARG gid=1000


## -----------------------------------------------------------------------------
## --- pre-work for interactive environment ------------------------------------
## -----------------------------------------------------------------------------

##### unminimize Ubuntu container image
###RUN yes | unminimize

## copy configs
COPY "./docker/dist/etc/default/keyboard" "/etc/default/keyboard"

##### system reference manuals (manual pages)
###RUN apt-get update \
###    && apt-get install --no-install-recommends -y \
###    man-db \
###    manpages-posix \
###    manpages-dev \
###    && rm -rf /var/lib/apt/lists/*

## Bash command completion
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*


## -----------------------------------------------------------------------------
## --- install dependencies ----------------------------------------------------
## -----------------------------------------------------------------------------

## install Python etc.
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    astyle \
    build-essential \
    cmake \
    doxygen \
    gcc \
    git \
    graphviz \
    libssl-dev \
    ninja-build \
    python3-dev \
    python3-pip \
    python3-pytest \
    python3-pytest-xdist \
    python3-venv \
    python3-yaml \
    unzip \
    valgrind \
    xsltproc \
    && rm -rf /var/lib/apt/lists/*

## liboqs
RUN git clone --depth=1 --recursive -b '0.7.2' \
	'https://github.com/open-quantum-safe/liboqs.git' '/opt/liboqs'
RUN mkdir -vp '/opt/liboqs/build'
WORKDIR '/opt/liboqs/build'
RUN cmake -GNinja .. -DBUILD_SHARED_LIBS=ON
RUN ninja && ninja install

## liboqs-python
RUN git clone --depth=1 --recursive -b '0.7.2' \
	'https://github.com/open-quantum-safe/liboqs-python.git' '/opt/liboqs-python'
WORKDIR '/opt/liboqs-python'
RUN python3 setup.py install
#ENV PYTHONPATH="$(pwd)"
ENV PYTHONPATH="${PYTHONPATH}:/opt/liboqs-python"


## -----------------------------------------------------------------------------
## --- setup user --------------------------------------------------------------
## -----------------------------------------------------------------------------

WORKDIR /

## install sudo and gosu
RUN apt-get update \
	&& apt-get install --no-install-recommends -y \
	gosu \
	sudo \
	&& rm -rf /var/lib/apt/lists/*

## create non-root user and grant sudo permission
RUN export user="${user}" uid="${uid}" gid="${gid}" \
	&& addgroup --gid "${gid}" "${user}" \
	&& adduser --home "/home/${user}" --uid "${uid}" --gid "${gid}" \
	--disabled-password --gecos '' "${user}" \
	&& mkdir -vp /etc/sudoers.d/ \
	&& echo "${user}     ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/${user}" \
	&& chmod 0440 /etc/sudoers.d/"${user}" \
	&& chown "${uid}:${gid}" -R /home/"${user}"


## -----------------------------------------------------------------------------
## --- setup PoC ---------------------------------------------------------------
## -----------------------------------------------------------------------------

## copy 'Proof-of-Concept' folder to container and install Python dependencies
COPY "./Proof-of-Concept" "/home/$user/poc/Proof-of-Concept"
WORKDIR "/home/$user/poc/Proof-of-Concept"
RUN python3 -m venv .venv \
    && . .venv/bin/activate \
    && pip install -r requirements.txt \
    && deactivate

## copy 'Evaluation' folder to container and install Python dependencies
COPY "./Evaluation" "/home/$user/poc/Evaluation"
WORKDIR "/home/$user/poc/Evaluation"
RUN python3 -m venv .venv \
    && . .venv/bin/activate \
    && pip install -r requirements.txt \
    && deactivate

## set permissions to user
RUN chown -R "${user}:${user}" "/home/$user/poc"


## -----------------------------------------------------------------------------
## --- configuration -----------------------------------------------------------
## -----------------------------------------------------------------------------

## Docker entrypoint
COPY "./docker/dist/usr/local/bin/docker-entrypoint.sh" "/usr/local/bin/"
## keep backwards compatibility
RUN ln -s '/usr/local/bin/docker-entrypoint.sh' /

## set environment variables
USER "$uid:$gid"
ENV HOME /home/"$user"
WORKDIR /home/"$user"/poc


## -----------------------------------------------------------------------------
## --- postamble ---------------------------------------------------------------
## -----------------------------------------------------------------------------

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]
