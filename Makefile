TARGET=cfddns
CC=cc

LIBS=-lcurl
ARCH=linux

PREFIX=/usr/local
BINDIR=${PREFIX}/bin

${TARGET}: Makefile ${TARGET}.c
	${CC} -Wall -g -D${ARCH} -DPREFIX=\"${PREFIX}\" ${TARGET}.c -o ${TARGET} ${LIBS}

install: ${TARGET}
	if [ ! -d ${BINDIR} ]; then mkdir -p ${BINDIR};fi
	cp ${TARGET} ${BINDIR}/${TARGET}
	cp ${TARGET}.service /etc/systemd/system/${TARGET}.service

clean:
	rm -f *.o
	rm -f ${TARGET}
