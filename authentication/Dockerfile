FROM ubuntu:latest 

RUN apt-get update && apt-get install -y \
    sudo \
    python3 \
    python3-pip \
    vim \
    net-tools \
    lsof \
    sqlite3

ENV newuser="admin"
RUN useradd -ms /bin/bash $newuser \
    && usermod -aG sudo $newuser \
    && echo "%sudo ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

USER $newuser

WORKDIR /home/$newuser

# sqlite db file is mounted, not copied
COPY requirements.txt authentication.py token_verifier.py ./db/create_tables.sql entrypoint.sh /home/${newuser}

RUN pip3 install awscli
RUN pip3 install -r requirements.txt

ENTRYPOINT [ "./entrypoint.sh" ]


