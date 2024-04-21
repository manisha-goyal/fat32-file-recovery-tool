#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

#pragma pack(push,1)
typedef struct {
    uint8_t BS_jmpBoot[3];
    uint8_t BS_OEMName[8];
    uint16_t BPB_BytsPerSec;
    uint8_t BPB_SecPerClus;
    uint16_t BPB_RsvdSecCnt;
    uint8_t BPB_NumFATs;
    uint8_t otherData[19];
} BootSector;
#pragma pack(pop)

void print_usage();
BootSector readBootSector(const char *diskImage);
void printFileSystemInfo(BootSector bootSector);

int main(int argc, char *argv[]) {
    int opt;
    char *filename = NULL;
    char *sha1 = NULL;
    int r_flag = 0, R_flag = 0, i_flag = 0, l_flag = 0, s_flag = 0;

    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1) {
        switch (opt) {
            case 'i':
                i_flag = 1;
                break;
            case 'l':
                l_flag = 1;
                break;
            case 'r':
                r_flag = 1;
                filename = optarg;
                break;
            case 'R':
                R_flag = 1;
                filename = optarg;
                break;
            case 's':
                s_flag = 1;
                sha1 = optarg;
                break;
            default:
                print_usage();
                return 1;
        }
    }

    if (optind >= argc) {
        print_usage();
        return 1;
    }

    char *diskImage = argv[optind];

    if ((i_flag && argc != 3) || (l_flag && argc != 3) || (r_flag && R_flag) ||
        (r_flag && !filename ) || (R_flag && (!filename || !s_flag || !sha1))) {
        print_usage();
        return 1;
    }

    if ((i_flag + l_flag + r_flag + R_flag) != 1) {
        print_usage();
        return 1;
    }

    if (i_flag || l_flag) {
        if (argc != 3) {
            print_usage();
            return 1;
        }
    } else if (r_flag) {
        if ((filename == NULL || strlen(filename) == 0) || (s_flag && (sha1 == NULL || strlen(sha1) == 0))) {
            print_usage();
            return 1;
        }
    } else if (R_flag) {
        if (filename == NULL || strlen(filename) == 0 || !s_flag || sha1 == NULL || strlen(sha1) == 0) {
            print_usage();
            return 1;
        }
    } else {
        print_usage();
        return 1;
    }

    BootSector bootSector = readBootSector(diskImage);

    if(i_flag) {
        printFileSystemInfo(bootSector);
    }

    return 0;
}

void print_usage() {
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
    exit(EXIT_SUCCESS);
}

BootSector readBootSector(const char *diskImage) {
    BootSector bootSector;
    int fd = open(diskImage, O_RDONLY);

    if (fd == -1) {
        perror("Error opening disk image");
        exit(EXIT_FAILURE);
    }

    if (read(fd, &bootSector, sizeof(BootSector)) != sizeof(BootSector)) {
        perror("Error reading boot sector");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
    
    return bootSector;
}

void printFileSystemInfo(BootSector bootSector) {
    printf("Number of FATs = %d\n", bootSector.BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", bootSector.BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", bootSector.BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", bootSector.BPB_RsvdSecCnt);
}

/* References:
https://people.cs.rutgers.edu/~pxk/416/notes/c-tutorials/getopt.html
https://www.cs.fsu.edu/~cop4610t/lectures/project3/Week11/Slides_week11.pdf
https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf
*/