FROM ubuntu

RUN apt-get update
RUN apt-get -y install build-essential
RUN apt-get -y install gdb
RUN apt-get -y install strace
RUN apt-get -y install ltrace
RUN apt-get -y install bsdmainutils
RUN apt-get -y install elfutils
RUN apt-get -y install binutils
RUN apt-get -y install libc6-dev-i386
RUN apt-get -y install vim

run echo 'set background=dark' >> /root/.vimrc
