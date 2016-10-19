CC = gcc -Wall -std=c99

main: pySM4.o sm4.o 
	$(CC) -shared pySM4.o sm4.o -o pySM4.so
pySM4.o ase.o: pySM4.c sm4.c
	$(CC) -c pySM4.c -I /usr/include/python2.6/ sm4.c -fPIC 
clean:
	rm -rf *.o *.so
