/*
 * This file is a simple experiment to see the behaviour on write and fsync
 * Don't forget to change some values below accordingly.
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
char* get_string(int len);
void init_tcp();
int check();

static int sockfd;
static struct sockaddr_in s_server;

int read_update_file_three(int method, int num_updating) {
    char cr[30];
    int cr_i = 0;
    struct timespec begin, end; 
    FILE* fp[3];
    char* fname[3];

    if(method > 3) {
        return -1;
    }

    int i =0;
    for (i = 0; i < 3; i++) {
        char* fnamer; 
        if (i == 0) {
            fnamer = "/tmp/update_";
        } else if (i == 1) {
            fnamer = "/tmp/update_";
        } else {
            fnamer = "/tmp/tmp2/update_";
        }
        char* tname = get_string(5);
        fname[i] = (char*) malloc(80);
        sprintf(fname[i], "%s%s.txt", fnamer, tname);
        

        // if file already exist
        if(access(fname[i], F_OK) == 0 ) {
            fp[i] = fopen(fname[i], "r");
            fscanf(fp[i], "%[^\n]", cr);
            printf("Read: %s\n", cr);
            cr_i = atoi(cr);
            fclose(fp[i]);
        } else {
            printf("Create new file..\n");
            fp[i] = fopen(fname[i], "w");
            fprintf(fp[i], "%d\n",0);
            fclose(fp[i]);
        }
    }
    

    clock_gettime(CLOCK_REALTIME, &begin);

    if(method == 1) {
        printf("Mode 1: fsync\n");
        for (i = 0; i < 3; i++) {
            fp[i] = fopen(fname[i], "w");
            setvbuf(fp[i], NULL, _IONBF, 0);
        }

        FILE* fpt;
        int randint = -1;

        for(i = 1; i < num_updating; i++) {
            // printf("Write %d\t", i + cr_i);
            randint = rand() % 3;
            fpt = fp[randint];
            rewind(fpt);
            char buf[10];

            sprintf(buf, "%d",  i + cr_i);
            printf("==== fwrite gonna be called on iteration %d to file %s\n", i, fname[randint]);
            // printf("==== fwrite gonna be called on iteration %d to file %s fd %d\n", i, fname[randint], fileno(fpt));
            fwrite(buf, strlen(buf), 1, fpt);
            printf("==== fsync gonna be called on iteration %d to file %s\n", i, fname[randint]);
            // printf("==== fsync gonna be called on iteration %d to file %s fd %d\n", i, fname[randint], fileno(fpt));
            fsync(fileno(fpt));
            // check();
        }
        fclose(fp[0]);
        fclose(fp[1]);
        fclose(fp[2]);
    } else {
        exit(1);
    }
    clock_gettime(CLOCK_REALTIME, &end);

    printf("\t\tLast written to disk: %d\n", i + cr_i - 1);
    printf("Time measured: %.3f seconds. Updated %d times\n", conv_elapsed_time(begin, end), num_updating);

    return 0;
}

int read_update_file(char* fname, int method, int num_updating) {
    char cr[30];
    int cr_i = 0;
    struct timespec begin, end; 
    int fp;

    if(method > 3) {
        return -1;
    }

    // if file already exist
    if(access(fname, F_OK) == 0 ) {
        FILE * fp;
        fp = fopen(fname, "r");
        fscanf(fp, "%[^\n]", cr);
        printf("Read: %s\n", cr);
        cr_i = atoi(cr);
        fclose(fp);
    } else {
        printf("Create new file..\n");
        FILE * fp;
        fp = fopen(fname, "w");
        fprintf(fp, "%d\n",0);
        fclose(fp);
    }

    int i = 0;

    clock_gettime(CLOCK_REALTIME, &begin);

    if(method == 1) {
        printf("Mode 1: fsync\n");
        // fp = open(fname, O_RDWR, 0);
        // setvbuf(fp, NULL, _IONBF, 0);
        for(i = 1; i < num_updating; i++) {
            // printf("Write %d\t", i + cr_i);
            // rewind(fp);
            // lseek(fp, 0, SEEK_SET);
            char buf[10];

            sprintf(buf, "%d",  i + cr_i);
            // printf("==== fwrite gonna be called on iteration %d\n", i);
            write(fp, buf, strlen(buf));
            // printf("==== fsync gonna be called on iteration %d\n", i);
            if (i % 1000 == 0) fsync(fp);
            // check();
        }
        // printf("done;");
        close(fp);
    } else {
        exit(1);
    }
    clock_gettime(CLOCK_REALTIME, &end);

    printf("\t\tLast written to disk: %d\n", i + cr_i - 1);
    printf("Time measured: %.3f seconds. Updated %d times\n", conv_elapsed_time(begin, end), num_updating);

    return 0;
}

int main(int argc, char *argv[])  {
    srand (time (NULL));
    setbuf(stdout, NULL);
    
    int num_updating = 100;
    if(argc < 2) {
        printf("prog <update file repetition>\n");
        exit(19);
    } else if(argc >= 3) {
        num_updating = atoi(argv[2]);
    }

    int upd = atoi(argv[1]);

    // sleep(2);
    // init_tcp();

    // char* fname = "/tmp/update_";
    // char* tname;
    // char* temp = malloc(80);

    for (int i = 0; i < upd; i++) {
        /**
         * 0 means do the close-reopen (oldish)
         * 1 means do the fsync each iteration(for CAS)
         * 2 means just close (for apps)
         * 3 means just fsync before close (for apps)
         */
        // tname = get_string(5);   
        // sprintf(temp, "%s%s.txt", fname, tname);
        // read_update_file_three(1, num_updating); 
        read_update_file("./update_f.txt", 1, num_updating); 

        // read_update_file("update_close.txt", 2); 
        // read_update_file("update_f-close.txt", 3); 
    }
    printf("\nDone.\n");
    return 0;
}

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
    long nanoseconds = end.tv_nsec - begin.tv_nsec;
    double elapsed = seconds + nanoseconds*1e-9;

    return elapsed;
}

char* get_string(int len) {
    const char ALLOWED[] = "abcdefghijklmnopqrstuvwxyz1234567890";
    char* random = malloc(len+1);
    int i = 0;
    int c = 0;
    int nbAllowed = sizeof(ALLOWED)-1;
    for(i=0;i<len;i++) {
        c = rand() % nbAllowed ;
        random[i] = ALLOWED[c];
    }
    random[len] = '\0';
    return random;
}

void init_tcp() {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        exit(1);
    }
    printf("Init callee...\n");
    memset(&s_server, 0, sizeof(s_server)); 
    s_server.sin_family = AF_INET;
    s_server.sin_port = htons(3333);
    s_server.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(connect(sockfd, (struct sockaddr*)&s_server, sizeof(s_server)) < 0){
        printf("Something went wrong %s\n", strerror(errno));
    }

    // if(inet_pton(AF_INET, "127.0.0.1", &s_server.sin_addr)<=0) { 
       
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
    printf("Init callee...\n");
    memset(&s_server, 0, sizeof(s_server)); 
    s_server.sin_family = AF_INET;
    s_server.sin_port = htons(3333);
    s_server.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(connect(sockfd, (struct sockaddr*)&s_server, sizeof(s_server)) < 0){
        printf("Something went wrong %s\n", strerror(errno));
    }

    // socklen_t len = sizeof(s_server);
    char buffer[INET_ADDRSTRLEN];
    // inet_ntop( AF_INET, &s_server.sin_addr, buffer, sizeof( buffer ));

    if(send(sockfd, cmd, strlen(cmd), 0) < 0){
        printf("Unable to send message\n");
        return -1;
    }
    // st = sendto(sockfd, (const char *) cmd, strlen(cmd), 0 ,(const struct sockaddr*)&s_server, sizeof(s_server));
    printf("ServoSent>> %s\t\t(len: %d)\n", cmd, st);
    // if(st == -1) {
    //     printf("Error sending: %i\n",errno);
    // }
    if(recv(sockfd, buffer, sizeof(buffer), 0) < 0){
        printf("Error while receiving server's msg\n");
        return -1;
    }
    // n = recvfrom(sockfd, (char *)buf, 1024,  MSG_WAITALL, (struct sockaddr *) &s_server, &len); 
    // buf[n] = '\0';

    printf("ServoGot>> %s \t\t(len: %d)\n", buf, n);
    close(sockfd);
    return 0;
}