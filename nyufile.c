#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

typedef struct DiskImage {
    char *filename;
    void *map;
    size_t size;
} DiskImage;

#define ATTR_DIRECTORY 0x10
#define ATTR_LONG_NAME 0x0f
#define DELETED_FILE 0xe5
#define EMPTY_DIRECTORY 0x00
#define END_OF_DIRECTORY 0x00
#define END_OF_CLUSTER 0x0ffffff8

void initDiskImage(DiskImage *diskImage, char *filename);
void mapDiskImage(DiskImage *diskImage);
void unmapDiskImage(DiskImage *diskImage);
void printUsage();
void printFileSystemInfo(BootEntry *bootEntry);
void listRootDirectory(BootEntry *bootEntry, char *diskMap);
char *formatDirEntryName(unsigned char *dirName);

int main(int argc, char *argv[]) {
    int opt;
    char *filename = NULL;
    char *sha1 = NULL;
    int rFlag = 0, RFlag = 0, iFlag = 0, lFlag = 0, sFlag = 0;

    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1) {
        switch (opt) {
            case 'i':
                iFlag = 1;
                break;
            case 'l':
                lFlag = 1;
                break;
            case 'r':
                rFlag = 1;
                filename = optarg;
                break;
            case 'R':
                RFlag = 1;
                filename = optarg;
                break;
            case 's':
                sFlag = 1;
                sha1 = optarg;
                break;
            default:
                printUsage();
        }
    }

    if (optind >= argc) {
        printUsage();
    }

    if ((iFlag + lFlag + rFlag + RFlag) != 1) {
        printUsage();
    }

    if (iFlag || lFlag) {
        if (argc != 3) {
            printUsage();
        }
    } else if (rFlag) {
        if ((filename == NULL || strlen(filename) == 0) || (sFlag && (sha1 == NULL || strlen(sha1) == 0))) {
            printUsage();
        }
    } else if (RFlag) {
        if (filename == NULL || strlen(filename) == 0 || !sFlag || sha1 == NULL || strlen(sha1) == 0) {
            printUsage();
        }
    } else {
        printUsage();
    }

    char *diskImageName = argv[optind];
    DiskImage diskImage;
    initDiskImage(&diskImage, diskImageName);
    mapDiskImage(&diskImage);

    BootEntry *bootEntry = (BootEntry *)diskImage.map;
    if (!bootEntry) {
        fprintf(stderr, "Failed to initialize disk image\n");
        exit(EXIT_FAILURE);
    }

    if(iFlag) {
        printFileSystemInfo(bootEntry);
    }
    if (lFlag) {
        listRootDirectory(bootEntry, diskImage.map);
    } 
    
    unmapDiskImage(&diskImage);

    return 0;
}

void initDiskImage(DiskImage *diskImage, char *filename) {
    diskImage->filename = filename;
    diskImage->map = MAP_FAILED;
    diskImage->size = 0;
}

void mapDiskImage(DiskImage *diskImage) {
    int fd = open(diskImage->filename, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "Error opening disk image");
        exit(EXIT_FAILURE);
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        close(fd);
        fprintf(stderr, "Error determining file size");
        exit(EXIT_FAILURE);
    }

    diskImage->size = sb.st_size;

    unmapDiskImage(diskImage);
    diskImage->map = mmap(NULL, diskImage->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (diskImage->map == MAP_FAILED) {
        fprintf(stderr, "Error mapping disk image");
        exit(EXIT_FAILURE);
    }
}

void unmapDiskImage(DiskImage *diskImage) {
    if (diskImage->map != MAP_FAILED) {
        munmap(diskImage->map, diskImage->size);
        diskImage->map = MAP_FAILED;
    }
}

void printUsage() {
    printf("Usage: ./nyufile disk <options>\n");
    printf("  -i                     Print the file system information.\n");
    printf("  -l                     List the root directory.\n");
    printf("  -r filename [-s sha1]  Recover a contiguous file.\n");
    printf("  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
    exit(EXIT_SUCCESS);
}

void printFileSystemInfo(BootEntry *bootEntry) {
    printf("Number of FATs = %d\n", bootEntry->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", bootEntry->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", bootEntry->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", bootEntry->BPB_RsvdSecCnt);
}

void listRootDirectory(BootEntry *bootEntry, char *diskMap) {
    unsigned int rootCluster = bootEntry->BPB_RootClus;
    unsigned int clusterSize = bootEntry->BPB_SecPerClus * bootEntry->BPB_BytsPerSec;
    unsigned int reservedSecOffset = bootEntry->BPB_RsvdSecCnt * bootEntry->BPB_BytsPerSec;
    unsigned int fatOffset = (bootEntry->BPB_NumFATs * bootEntry->BPB_FATSz32) * bootEntry->BPB_BytsPerSec;
    unsigned int *FAT = (unsigned int *)(diskMap + reservedSecOffset);
    int entriesPerCluster = (int)(clusterSize/sizeof(DirEntry));

    int totalEntries = 0;

    while (rootCluster < END_OF_CLUSTER) {
        unsigned int clusterOffset = ((rootCluster - 2) * clusterSize) + reservedSecOffset + fatOffset;
        DirEntry *entry = (DirEntry *)(diskMap + clusterOffset);
        int entryCount = 0;
        int validEntryCount = 0;

        while(entryCount < entriesPerCluster && entry->DIR_Name[0] != END_OF_DIRECTORY && entry->DIR_Attr != EMPTY_DIRECTORY) {
            if (entry->DIR_Name[0] == DELETED_FILE || entry->DIR_Attr == ATTR_LONG_NAME) {
                entry++;
                entryCount++;
                continue;
            }

            char *formattedName = formatDirEntryName(entry->DIR_Name);
            unsigned int startingCluster = ((unsigned int)entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;

            if (entry->DIR_Attr == ATTR_DIRECTORY) {
                printf("%s/ (starting cluster = %u)\n", formattedName, startingCluster);
            } else {
                if (entry->DIR_FileSize != 0){ 
                    printf("%s (size = %u, starting cluster = %u)\n", formattedName, entry->DIR_FileSize, startingCluster);
                } else {
                    printf("%s (size = %u)\n", formattedName, entry->DIR_FileSize);
                }
            }

            if (formattedName != NULL) {
                free(formattedName);
            }

            entry++;
            entryCount++;
            validEntryCount++;
        }

        totalEntries+=validEntryCount;
        rootCluster = FAT[rootCluster];
    }
    
    printf("Total number of entries = %d\n", totalEntries);
}

char *formatDirEntryName(unsigned char* dirName) {
    char* formattedName = malloc(13 * sizeof(char));
    int len = 0, pos = 0;

    while (pos < 8 && dirName[pos] != ' ') {
        formattedName[len++] = dirName[pos++];
    }

    int hasExtension = 0;
    pos = 8;
    while (pos < 11 && !hasExtension) {
        if (dirName[pos] != ' ') {
            hasExtension = 1;
        }
        pos++;
    }

    if (hasExtension) {
        formattedName[len++] = '.';
        pos = 8;
        while (pos < 11 && dirName[pos] != ' ') {
            formattedName[len++] = dirName[pos++];
        }
    }

    formattedName[len] = '\0';
    return formattedName;
}

/* References:
https://people.cs.rutgers.edu/~pxk/416/notes/c-tutorials/getopt.html
https://www.cs.fsu.edu/~cop4610t/lectures/project3/Week11/Slides_week11.pdf
https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf
https://www.rapidtables.com/convert/number/ascii-to-hex.html
https://people.cs.umass.edu/~liberato/courses/2017-spring-compsci365/lecture-notes/11-fats-and-directory-entries/
https://averstak.tripod.com/fatdox/dir.htm#atr
*/