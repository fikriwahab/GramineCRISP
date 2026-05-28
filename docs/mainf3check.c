/**
 * This file is a simple experiment to check disk write/read which you can modify :
 *  - file size (hardcoded)
 *  - buffer size
 *  - how often we want to do fsync
 *  - whether to call fwrite(libc) or write(syscall) - hardcoded
 *  - on how to call the checker API on scone runtime
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h> 
#include <time.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define DIM(x) (sizeof(x)/sizeof(*(x)))
static const char     *sizes[]   = { "EiB", "PiB", "TiB", "GiB", "MiB", "KiB", "B" };
static const uint64_t  exbibytes = 1024ULL * 1024ULL * 1024ULL *
                                   1024ULL * 1024ULL * 1024ULL;

char * calculateSize(uint64_t size);
double conv_elapsed_time(struct timespec begin, struct timespec end );

int check();
static int sockfd;
static struct sockaddr_in s_server;

uint64_t randr(uint64_t min, uint64_t max) {
    double scaled = (double)rand()/RAND_MAX;
    return (max - min +1)*scaled + min;
}
int write_file3(char* fname, uint64_t fsize, uint64_t bufsize, int fsync_size, int prob);

int read_file(char* fname, uint64_t bufsize) {
    int times = 0;
    unsigned char *a = (unsigned char *)calloc( bufsize, sizeof(unsigned char) );

    struct timespec begin, end; 
    clock_gettime(CLOCK_REALTIME, &begin);

    int fd = open(fname, O_RDONLY, 0);  
    while (read(fd, a, bufsize) > 0 ){
        // printf("==== Read was called on iteration %d\n", times);
        times++;
    }
    close(fd);
    free(a);
    clock_gettime(CLOCK_REALTIME, &end);

    uint64_t fsize = times * bufsize;
    double elapsed = conv_elapsed_time(begin, end);
    printf("\t\tRead %d * %ld = %lu (%s)\n", times, bufsize, fsize, calculateSize(fsize));
    printf("\t\tTime measured: %.3f mseconds.\n", elapsed);
    printf("Read %s per msecond\n", calculateSize(fsize/elapsed));
}


int main(int argc, char *argv[])  {
    srand((unsigned)clock());
    setbuf(stdout, NULL);

    int block_size = 4096;
    uint64_t target_fsize = 256;
    int fsync_iter = 100 * 1024; 
    int prob = 50;

    if (argc < 2) {
        printf("prog <block size :4096> <fsync_size:10> \n");
        printf("[INFO] use default blocksize and fsync_size\n");
    } else if (argc < 3) {
        block_size = atoi(argv[1]);
        printf("[INFO] use default fsync_size and prob\n");
    } else if (argc < 4) {
        block_size = atoi(argv[1]);
        fsync_iter = atoi(argv[2]);
        printf("[INFO] use default prob\n");
    } else {
        block_size = atoi(argv[1]);
        fsync_iter = atoi(argv[2]);
        prob = atoi(argv[3]);
    }
    printf("Block size : %d\n", block_size);
    fsync_iter = -1;
    printf("IGNORED (SAME AS BLOCK SIZE): Fsync size : %d\n", -1);
    printf("Prob : %d\n", prob);
    
    /**
     * if you want to make the filesize varies, modify these 3 lines.
     */
    // in mb ( * 1024^2 )
    uint64_t minsizes[] = {10, 90, 200, 900};
    uint64_t maxsizes[] = {20, 110, 400, 1100};
    int lensize = 1; // len(minsizes) == len(maxsizes)
    // hardcode ends

    int i = 0;
    for(i = 0; i < lensize; i++) {
        uint64_t randNum = target_fsize;
        char* numstr;
        char buffer[1024];

        asprintf(&numstr, "%ld", randNum);
        strcat(strcpy(buffer, "write"), numstr);
        strcat(buffer, ".bin");

        // do write
        printf("Writing:\n");
        write_file3(buffer, 
            randNum * 1024 * 1024, 
            block_size, fsync_iter, prob); 

        printf("Reading:\n");
        // do read
        read_file(buffer, block_size);
        
        remove(buffer);
        free(numstr);
    }
    printf("\n\n");
    printf("\nDone.\n");
    return 0;
}

// utility

char * calculateSize(uint64_t size) {   // source : https://stackoverflow.com/a/3898986
    char     *result = (char *) malloc(sizeof(char) * 20);
    uint64_t  multiplier = exbibytes;
    int i;

    for (i = 0; i < DIM(sizes); i++, multiplier /= 1024)
    {   
        if (size < multiplier)
            continue;
        if (size % multiplier == 0)
            sprintf(result, "%" PRIu64 " %s", size / multiplier, sizes[i]);
        else
            sprintf(result, "%.1f %s", (float) size / multiplier, sizes[i]);
        return result;
    }
    strcpy(result, "0");
    return result;
}

double conv_elapsed_time(struct timespec begin, struct timespec end ) {
    long seconds = end.tv_sec - begin.tv_sec;
    long mseconds = seconds * 1000;

    long nanoseconds = end.tv_nsec - begin.tv_nsec;
    double elapsed = mseconds + nanoseconds*1e-6;

    return elapsed;
}

int check() {
    char* cmd = "CHECK\n";
    char buf[1024];
    memset(buf, 0, 1024);
    int n, st;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        exit(1);
    }
    // printf("Init callee...\n");
    memset(&s_server, 0, sizeof(s_server)); 
    s_server.sin_family = AF_INET;
    s_server.sin_port = htons(3333);
    s_server.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(connect(sockfd, (struct sockaddr*)&s_server, sizeof(s_server)) < 0){
        close(sockfd);
        // printf("Something went wrong %s\n", strerror(errno));
        return -1;
    }

    // socklen_t len = sizeof(s_server);
    char buffer[INET_ADDRSTRLEN];
    // inet_ntop( AF_INET, &s_server.sin_addr, buffer, sizeof( buffer ));

    if(send(sockfd, cmd, strlen(cmd), 0) < 0){
        printf("Unable to send message\n");
        return -1;
    }
    // st = sendto(sockfd, (const char *) cmd, strlen(cmd), 0 ,(const struct sockaddr*)&s_server, sizeof(s_server));
    // printf("ServoSent>> %s\t\t(len: %d)\n", cmd, st);
    // if(st == -1) {
    //     printf("Error sending: %i\n",errno);
    // }
    if(recv(sockfd, buffer, sizeof(buffer), 0) < 0){
        printf("Error while receiving server's msg\n");
        return -1;
    }
    // n = recvfrom(sockfd, (char *)buf, 1024,  MSG_WAITALL, (struct sockaddr *) &s_server, &len); 
    // buf[n] = '\0';

    // printf("ServoGot>> %s \t\t(len: %d)\n", buf, n);
    close(sockfd);
    return 0;
}

int write_file3(char* fname, uint64_t fsize, uint64_t bufsize, int fsync_size, int prob) {
    // fill with random stuff
    unsigned char a[bufsize];
    for(uint64_t i = 0; i < bufsize; i++) {
        a[i] = i % 255; 
    }

    
    
    // how many we need to repeat per block
    int times = fsize/bufsize + 1; 
    int check_times = 0;

    // only count 'open-and-write' part
    struct timespec begin, end; 
    clock_gettime(CLOCK_REALTIME, &begin);

    // pick either FILE or fd
    // FILE* f = fopen(fname, "w");
    int fd = open(fname, O_WRONLY | O_CREAT, 0777);

    if (fd < 0) { // (f == NULL) {
        printf("%d\n", errno);
        exit(errno);
    }

    for(int loop = 1; loop <= times; ++loop) {   

        // make things spicy a bit
        a[loop % bufsize] = a[loop % bufsize] * 3;
        a[(loop*2) % bufsize] = a[(loop*2) % bufsize] * 7;

        write(fd, a, bufsize);
        fsync(fd);

        int a = rand() / (RAND_MAX / 100 + 1);
        if (a <= prob) {
            check();
            check_times++;
        }
    }  
    
    close(fd);
    clock_gettime(CLOCK_REALTIME, &end);

    double elapsed = conv_elapsed_time(begin, end);

    printf("\t\tWrite %d * %ld = %lu (%s)\n", times, bufsize, times * bufsize, calculateSize(times * bufsize));
    printf("\t\tTime measured: %.3f mseconds.\n", elapsed);
    printf("Write %s per msecond\n", calculateSize((times * bufsize)/elapsed));
    printf("Iter %d times with size %d floop %d check %d\n", 0, 0, 0, check_times);
    return 0;
}
