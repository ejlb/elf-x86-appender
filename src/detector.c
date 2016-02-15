#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <error.h>

#define SIG_LEN 15

// entry point patching code
unsigned char signature[SIG_LEN] = {
    0x81, 0x3b, 0x31, 0xff, 0x31, 
    0xf6, 0x75, 0x0b, 0x81, 0x7b,
    0x04, 0xb0, 0x01, 0x31, 0xdb
};

int sig_match(unsigned char *buffer, unsigned char *sig, int len) {
    int i = 0;
    for(i = 0; i < len; i++) {
        if(buffer[i] != sig[i]) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("%s <file>\n", argv[0]);
        exit(-1);
    }

    unsigned char buffer[SIG_LEN];
    int fd;

    if((fd = open(argv[1], O_RDONLY)) == -1) {
        perror("open()");
        exit(-1);
    }

    while(read(fd, buffer, SIG_LEN) > 0) {
        if(sig_match(buffer, signature, SIG_LEN)) {
            printf("%s is infected\n", argv[1]);
            return 1;
        }

        if(read(fd, buffer, 1) == 0)
            break;
        lseek(fd, -(SIG_LEN), SEEK_CUR);
    }

    printf("%s is clean\n", argv[1]);
    close(fd);
    return 0;
}

