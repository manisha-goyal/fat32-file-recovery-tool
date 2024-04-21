#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>

void print_usage();
void print_file_system_info(const char *diskImage);

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
        if(i_flag) {
            print_file_system_info(diskImage);
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

    return 0;
}

void print_file_system_info(const char *diskImage) {
    //add code here
    printf(diskImage);
}

void print_usage() {
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
    exit(0);
}

/* References:

https://people.cs.rutgers.edu/~pxk/416/notes/c-tutorials/getopt.html


*/