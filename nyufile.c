#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <openssl/sha.h>

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
    char *diskMap;
    size_t size;
    BootEntry *bootEntry;
    unsigned int rootCluster;
    unsigned int clusterSize;
    unsigned int reservedSecOffset;
    unsigned int fatOffset;
    int fatCount;
    unsigned int fatSize;
    unsigned int *FAT;
    int entriesPerCluster;
} DiskImage;

#define ATTR_DIRECTORY 0x10
#define ATTR_LONG_NAME 0x0f
#define DELETED_FILE 0xe5
#define EMPTY_DIRECTORY 0x00
#define END_OF_DIRECTORY 0x00
#define END_OF_CLUSTER 0x0ffffff8
#define SHA_DIGEST_LENGTH 20

#define EMPTY_FILE_SHA1 "da39a3ee5e6b4b0d3255bfef95601890afd80709"

#define MAX_CLUSTERS 20
#define MAX_FILE_CLUSTERS 5

void handleError(char* message, int exitCode);
void mapDiskImage(DiskImage *diskImage, char *filename);
void unmapDiskImage(DiskImage *diskImage);

void printUsage();
void printFileSystemInfo(DiskImage *diskImage);
void listRootDirectory(DiskImage *diskImage);
void recoverContiguousFile(DiskImage *diskImage, char *filename, int sFlag, char *sha1);
void recoverNonContiguousFile(DiskImage *diskImage, char *filename, char *sha1);

unsigned int getStartingCluster(DirEntry *entry);
char *formatDirEntryName(unsigned char *dirName, bool overrideFirstChar, char firstChar);
bool isMatchingDeletedFile(unsigned char* entryName, char* filename);

bool checkSHA1MatchContiguousFile(DiskImage *diskImage, DirEntry *entry, const char *expectedSHA1);

bool isMatchingDeletedFileClusters(DiskImage *diskImage, DirEntry *entry, char *sha1, unsigned int *fileClusters);
bool findDeletedFileClusters(DiskImage *diskImage, unsigned int fileSize, unsigned int *unallocatedClusters, int unallocatedClusterCount, unsigned int *fileClusters, int fileClusterCount, char *sha1);
bool checkSHA1MatchNonContiguousFile(DiskImage *diskImage, unsigned int *fileClusters, int fileClusterCount, unsigned int fileSize, char *sha1);

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

    char *diskImageName = argv[optind];

    DiskImage diskImage;
    mapDiskImage(&diskImage, diskImageName);

    if (iFlag) {
        if (argc != 3) {
            printUsage();
        }
        printFileSystemInfo(&diskImage);
    } else if (lFlag) {
        if (argc != 3) {
            printUsage();
        }
        listRootDirectory(&diskImage);
    } else if (rFlag) {
        if ((filename == NULL || strlen(filename) < 1) || (sFlag && (sha1 == NULL || strlen(sha1) == 0))) {
            printUsage();
        }
        recoverContiguousFile(&diskImage, filename, sFlag, sha1);
    } else if (RFlag) {
        if (filename == NULL || strlen(filename) < 1 || !sFlag || sha1 == NULL || strlen(sha1) == 0) {
            printUsage();
        }
        recoverNonContiguousFile(&diskImage, filename, sha1);
    } else {
        printUsage();
    }

    unmapDiskImage(&diskImage);
    return 0;
}

void handleError(char* message, int exitCode) {
    fprintf(stderr, "%s\n", message);
    if (exitCode != 0) {
        exit(exitCode);
    }
}

void mapDiskImage(DiskImage *diskImage, char *filename) {
    diskImage->filename = filename;

    int fd = open(diskImage->filename, O_RDWR);
    if (fd == -1) {
        handleError("Error opening disk image", EXIT_FAILURE);
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        close(fd);
        handleError("Error determining file size", EXIT_FAILURE);
    }

    diskImage->size = sb.st_size;
    diskImage->diskMap = mmap(NULL, diskImage->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);

    if (diskImage->diskMap == MAP_FAILED) {
        handleError("Error mapping disk image", EXIT_FAILURE);
    }

    diskImage->bootEntry = (BootEntry *)diskImage->diskMap;
    diskImage->rootCluster = diskImage->bootEntry->BPB_RootClus;
    diskImage->clusterSize = diskImage->bootEntry->BPB_SecPerClus * diskImage->bootEntry->BPB_BytsPerSec;
    diskImage->reservedSecOffset = diskImage->bootEntry->BPB_RsvdSecCnt * diskImage->bootEntry->BPB_BytsPerSec;
    diskImage->fatOffset = (diskImage->bootEntry->BPB_NumFATs * diskImage->bootEntry->BPB_FATSz32) * diskImage->bootEntry->BPB_BytsPerSec;
    diskImage->FAT = (unsigned int *)(diskImage->diskMap + diskImage->reservedSecOffset);
    diskImage->fatCount = diskImage->bootEntry->BPB_NumFATs;
    diskImage->fatSize = diskImage->bootEntry->BPB_FATSz32 * diskImage->bootEntry->BPB_BytsPerSec;
    diskImage->entriesPerCluster = (int)(diskImage->clusterSize / sizeof(DirEntry));
}

void unmapDiskImage(DiskImage *diskImage) {
    if (diskImage->diskMap != MAP_FAILED) {
        munmap(diskImage->diskMap, diskImage->size);
        diskImage->diskMap = MAP_FAILED;
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

void printFileSystemInfo(DiskImage *diskImage) {
    BootEntry *bootEntry = diskImage->bootEntry;

    printf("Number of FATs = %d\n", bootEntry->BPB_NumFATs);
    printf("Number of bytes per sector = %d\n", bootEntry->BPB_BytsPerSec);
    printf("Number of sectors per cluster = %d\n", bootEntry->BPB_SecPerClus);
    printf("Number of reserved sectors = %d\n", bootEntry->BPB_RsvdSecCnt);
}

void listRootDirectory(DiskImage *diskImage) {
    unsigned int rootCluster = diskImage->rootCluster;
    int totalEntries = 0;

    while (rootCluster < END_OF_CLUSTER) {
        unsigned int clusterOffset = ((rootCluster - 2) * diskImage->clusterSize) + diskImage->reservedSecOffset + diskImage->fatOffset;
        DirEntry *entry = (DirEntry *)(diskImage->diskMap + clusterOffset);
        int validEntryCount = 0;

        for (int i = 0; i < diskImage->entriesPerCluster && entry->DIR_Name[0] != END_OF_DIRECTORY && entry->DIR_Attr != EMPTY_DIRECTORY; i++, entry++) {
            if (entry->DIR_Name[0] == DELETED_FILE || entry->DIR_Attr == ATTR_LONG_NAME) {
                continue;
            }

            char *formattedName = formatDirEntryName(entry->DIR_Name, false, '\0');
            unsigned int startingCluster = getStartingCluster(entry);

            if (entry->DIR_Attr == ATTR_DIRECTORY) {
                printf("%s/ (starting cluster = %u)\n", formattedName, startingCluster);
            } else {
                if (entry->DIR_FileSize != 0){ 
                    printf("%s (size = %u, starting cluster = %u)\n", formattedName, entry->DIR_FileSize, startingCluster);
                } else {
                    printf("%s (size = %u)\n", formattedName, entry->DIR_FileSize);
                }
            }

            free(formattedName);
            validEntryCount++;
        }

        totalEntries+=validEntryCount;
        rootCluster = diskImage->FAT[rootCluster];
    }
    
    printf("Total number of entries = %d\n", totalEntries);
}

void recoverContiguousFile(DiskImage *diskImage, char *filename, int sFlag, char *sha1) {
    unsigned int rootCluster = diskImage->rootCluster;

    int matchingDeletedFileCount = 0;
    bool foundMatchingSHA1 = false;
    DirEntry *matchingDeletedEntry = NULL;

    while (rootCluster < END_OF_CLUSTER && !foundMatchingSHA1) {
        unsigned int clusterOffset = ((rootCluster - 2) * diskImage->clusterSize) + diskImage->reservedSecOffset + diskImage->fatOffset;
        DirEntry *entry = (DirEntry *)(diskImage->diskMap + clusterOffset);

        for (int i = 0; i < diskImage->entriesPerCluster && entry->DIR_Name[0] != END_OF_DIRECTORY && entry->DIR_Attr != EMPTY_DIRECTORY && !foundMatchingSHA1; i++, entry++) {
            if (entry->DIR_Attr == ATTR_LONG_NAME || entry->DIR_Attr == ATTR_DIRECTORY){
                continue;
            }

            if (entry->DIR_Name[0] == DELETED_FILE) {
                if (isMatchingDeletedFile(entry->DIR_Name, filename)) {
                    if(sFlag) {
                        if (checkSHA1MatchContiguousFile(diskImage, entry, sha1)) {
                            foundMatchingSHA1 = true;
                            matchingDeletedFileCount++;
                            matchingDeletedEntry = entry;
                        }
                    } else {
                        matchingDeletedFileCount++;
                        matchingDeletedEntry = entry;
                    }
                }
            }
        }
        rootCluster = diskImage->FAT[rootCluster];
    }

    if (matchingDeletedFileCount == 1) {
        unsigned int startingCluster = getStartingCluster(matchingDeletedEntry);
        int clustersToUpdate = (matchingDeletedEntry->DIR_FileSize + diskImage->clusterSize - 1) / diskImage->clusterSize;

        matchingDeletedEntry->DIR_Name[0] = filename[0];

        for(int i = 0; i < diskImage->fatCount; i++) {
            unsigned int *FAT = (unsigned int *)(diskImage->diskMap + diskImage->reservedSecOffset + (i * diskImage->fatSize));
            unsigned int cluster = startingCluster;
            for (int j = 0; j < clustersToUpdate - 1; j++) {
                FAT[cluster] = cluster + 1;
                cluster++;
            }
            FAT[cluster] = END_OF_CLUSTER;
        }

        if(foundMatchingSHA1) {
            printf("%s: successfully recovered with SHA-1\n", filename);
        } else {
            printf("%s: successfully recovered\n", filename);
        }
    } else if (matchingDeletedFileCount > 1) {
        printf("%s: multiple candidates found\n", filename);
    } else {
        printf("%s: file not found\n", filename);
    }
}

void recoverNonContiguousFile(DiskImage *diskImage, char *filename, char *sha1) {
    unsigned int rootCluster = diskImage->rootCluster;

    bool foundMatchingSHA1 = false;
    DirEntry *matchingDeletedEntry = NULL;
    unsigned int deletedFileClusters[MAX_FILE_CLUSTERS];
    memset(deletedFileClusters, 0, MAX_FILE_CLUSTERS * sizeof(unsigned int));

    while (rootCluster < END_OF_CLUSTER && !foundMatchingSHA1) {
        unsigned int clusterOffset = ((rootCluster - 2) * diskImage->clusterSize) + diskImage->reservedSecOffset + diskImage->fatOffset;
        DirEntry *entry = (DirEntry *)(diskImage->diskMap + clusterOffset);

        for (int i = 0; i < diskImage->entriesPerCluster && entry->DIR_Name[0] != END_OF_DIRECTORY && entry->DIR_Attr != EMPTY_DIRECTORY && !foundMatchingSHA1; i++, entry++) {
            if (entry->DIR_Attr == ATTR_LONG_NAME || entry->DIR_Attr == ATTR_DIRECTORY){
                continue;
            }

            if (entry->DIR_Name[0] == DELETED_FILE) {
                if (isMatchingDeletedFile(entry->DIR_Name, filename)) {
                    if(isMatchingDeletedFileClusters(diskImage, entry, sha1, deletedFileClusters)) {
                        foundMatchingSHA1 = true;
                        matchingDeletedEntry = entry;
                    }
                }
            }
        }
        rootCluster = diskImage->FAT[rootCluster];
    }

    if (foundMatchingSHA1) {
        matchingDeletedEntry->DIR_Name[0] = filename[0];

        int numClusters = matchingDeletedEntry->DIR_FileSize == 0 ? 1 : (matchingDeletedEntry->DIR_FileSize + diskImage->clusterSize - 1) / diskImage->clusterSize;
        
        for(int i = 0; i < diskImage->fatCount; i++) {
            unsigned int *FAT = (unsigned int *)(diskImage->diskMap + diskImage->reservedSecOffset + (i * diskImage->fatSize));
            for (int j = 0; j < numClusters - 1; j++) {
                FAT[deletedFileClusters[j]] = deletedFileClusters[j + 1];
            }
            FAT[deletedFileClusters[numClusters - 1]] = END_OF_CLUSTER;
        }

        printf("%s: successfully recovered with SHA-1\n", filename);
    } else {
        printf("%s: file not found\n", filename);
    }
}

unsigned int getStartingCluster(DirEntry *entry) {
    return ((unsigned int)entry->DIR_FstClusHI << 16) | entry->DIR_FstClusLO;
}

char *formatDirEntryName(unsigned char* dirName, bool overrideFirstChar, char firstChar) {
    char* formattedName = malloc(13 * sizeof(char));
    int len = 0;
    formattedName[len++] = overrideFirstChar ? firstChar : dirName[0];
    int pos = 1;

    while (pos < 8 && dirName[pos] != ' ') {
        formattedName[len++] = dirName[pos++];
    }

    bool hasExtension = false;
    for (pos = 8; pos < 11; pos++) {
        if (dirName[pos] != ' ') {
            hasExtension = true;
            break;
        }
    }

    if (hasExtension) {
        formattedName[len++] = '.';
        for (pos = 8; pos < 11 && dirName[pos] != ' '; pos++) {
            formattedName[len++] = dirName[pos];
        }
    }

    formattedName[len] = '\0';
    return formattedName;
}

bool isMatchingDeletedFile(unsigned char* entryName, char* filename) {
    char* recoveredName = formatDirEntryName(entryName, true, filename[0]);

    if (strcmp(recoveredName, filename) == 0) {
        free(recoveredName);
        return true;
    }

    free(recoveredName);
    return false;
}

bool checkSHA1MatchContiguousFile(DiskImage *diskImage, DirEntry *entry, const char *expectedSHA1) {
    if (entry->DIR_FileSize == 0) {
        return strncmp(EMPTY_FILE_SHA1, expectedSHA1, SHA_DIGEST_LENGTH * 2) == 0;
    }

    unsigned int startingCluster = getStartingCluster(entry);
    char *fileData = (char *)(diskImage->diskMap + ((startingCluster - 2) * diskImage->clusterSize) + diskImage->reservedSecOffset + diskImage->fatOffset);

    unsigned char shaDigest[SHA_DIGEST_LENGTH];
    char calculatedSHA1[SHA_DIGEST_LENGTH * 2 + 1];
    SHA1((unsigned char *)fileData, entry->DIR_FileSize, shaDigest);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(calculatedSHA1 + i * 2, "%02x", shaDigest[i]);
    }

    return strncmp(calculatedSHA1, expectedSHA1, SHA_DIGEST_LENGTH * 2) == 0;
}

bool isMatchingDeletedFileClusters(DiskImage *diskImage, DirEntry *entry, char *expectedSHA1, unsigned int *fileClusters) {
    memset(fileClusters, 0, MAX_FILE_CLUSTERS * sizeof(unsigned int));
    unsigned int startingCluster = getStartingCluster(entry);
    fileClusters[0] = startingCluster;

    if(entry->DIR_FileSize == 0) {
        return strncmp(EMPTY_FILE_SHA1, expectedSHA1, SHA_DIGEST_LENGTH * 2) == 0;
    }

    unsigned int unallocatedClusters[MAX_CLUSTERS];
    int unallocatedClusterCount = 0;
    for (int i = diskImage->rootCluster; i <= (int)(MAX_CLUSTERS + diskImage->rootCluster); i++) {
        if (diskImage->FAT[i] == 0) {
            unallocatedClusters[unallocatedClusterCount++] = i;
        }
    }
    
    return findDeletedFileClusters(diskImage, entry->DIR_FileSize, unallocatedClusters, unallocatedClusterCount, fileClusters, 1, expectedSHA1);
}

bool findDeletedFileClusters(DiskImage *diskImage, unsigned int fileSize, unsigned int *unallocatedClusters, int unallocatedClusterCount, unsigned int *fileClusters, int fileClusterCount, char *expectedSHA1) {
    if (fileSize <= diskImage->clusterSize * fileClusterCount) {
        if (checkSHA1MatchNonContiguousFile(diskImage, fileClusters, fileClusterCount, fileSize, expectedSHA1)) {
            return true;
        }
    } else {
        for (int i = 0; i < unallocatedClusterCount; i++) {
            bool contains = false;
            for (int j = 0; j < fileClusterCount && !contains; j++) {
                if (fileClusters[j] == unallocatedClusters[i]) {
                    contains = true;
                }
            }
            if (!contains) {
                fileClusters[fileClusterCount] = unallocatedClusters[i];
                if (findDeletedFileClusters(diskImage, fileSize, unallocatedClusters, unallocatedClusterCount, fileClusters, fileClusterCount + 1, expectedSHA1)) {
                    return true;
                }
                fileClusters[fileClusterCount] = 0;
            }
        }
    }

    return false;
}

bool checkSHA1MatchNonContiguousFile(DiskImage *diskImage, unsigned int *clusters, int numClusters, unsigned int fileSize, char *expectedSHA1) {
    char *data = malloc(fileSize * sizeof(char));
    unsigned int bytesRead = 0;

    for (int i = 0; i < numClusters; i++) {
        unsigned int clusterOffset = ((clusters[i] - 2) * diskImage->clusterSize) + diskImage->reservedSecOffset + diskImage->fatOffset;
        unsigned int bytesToRead = diskImage->clusterSize;

        if (bytesRead + bytesToRead > fileSize) {
            bytesToRead = fileSize - bytesRead;
        }

        memcpy(data + bytesRead, diskImage->diskMap + clusterOffset, bytesToRead);
        bytesRead += bytesToRead;

        if (bytesRead >= fileSize) {
            break;
        }
    }

    unsigned char shaDigest[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)data, fileSize, shaDigest);

    char calculatedSHA1[SHA_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(calculatedSHA1 + i * 2, "%02x", shaDigest[i]);
    }

    free(data);
    return strncmp(calculatedSHA1, expectedSHA1, SHA_DIGEST_LENGTH * 2) == 0;
}

/* References:
https://people.cs.rutgers.edu/~pxk/416/notes/c-tutorials/getopt.html
https://www.cs.fsu.edu/~cop4610t/lectures/project3/Week11/Slides_week11.pdf
https://academy.cba.mit.edu/classes/networking_communications/SD/FAT.pdf
https://www.rapidtables.com/convert/number/ascii-to-hex.html
https://people.cs.umass.edu/~liberato/courses/2017-spring-compsci365/lecture-notes/11-fats-and-directory-entries/
https://averstak.tripod.com/fatdox/dir.htm#atr
https://www.geeksforgeeks.org/difference-strncmp-strcmp-c-cpp/#:~:text=The%20basic%20difference%20between%20these,strncmp%20behaves%20similar%20to%20strcmp.
https://stackoverflow.com/questions/9284420/how-to-use-sha1-hashing-in-c-programming
https://stackoverflow.com/questions/6357031/how-do-you-convert-a-byte-array-to-a-hexadecimal-string-in-c
*/