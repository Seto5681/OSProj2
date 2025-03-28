/* 3/27/2025, 8:35 PM Disregard this file, im in the middle of a brute force test - Bryan */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <pthread.h> // New include!
#include <semaphore.h> //New include!

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept

/* This file currently just meant to be the commentless version of hash.c
Not completely commentless, just removes the big blocks to make typing things easy.  */

struct cracked_hash {
	char hash[2*KEEP+1];
	char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);
int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"}; // Names of hash functions used
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//Defining the reader-writer lock for future use

typedef struct _rwlock_t{
    sem_t lock; // binary semaphore (basic lock)
    sem_t writelock; // allow ONE writer/MANY readers
    int readers; // #readers in critical section
} rwlock_t;

void rwlock_init(rwlock_t *rw) {
    rw->readers = 0;
    sem_init(&rw->lock, 0, 1);
    sem_init(&rw->writelock, 0, 1);
}

void rwlock_acquire_readlock(rwlock_t *rw) {
    sem_wait(&rw->lock);
    rw->readers++;
    if (rw->readers == 1) {sem_wait(&rw->writelock); }         // first reader gets writelock
    sem_post(&rw->lock);
}

void rwlock_release_readlock(rwlock_t *rw) {
    sem_wait(&rw->lock);
    rw->readers--;
    if (rw->readers == 0){ sem_post(&rw->writelock); }               // last reader lets it go
    sem_post(&rw->lock);
}

void rwlock_acquire_writelock(rwlock_t *rw) {
    sem_wait(&rw->writelock);
}

void rwlock_release_writelock(rwlock_t *rw) {
    sem_post(&rw->writelock);
 }
    

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
struct pList {
	char *password;
	struct pList *next;
};

struct pList *pTSent; // pTSent for "passwordTailSentinel". Similar idea below
struct pList *pHSent; 
struct pList *allPWords;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int numHashed; //Number of hashes to check
struct hPAList {
	struct cracked_hash *entry;
	struct hPAList *next;
};

struct hPAList *tailSentinel; 
struct hPAList *headSentinel;
struct hPAList *allHashes;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

struct hPALIst *mD5Conversion;
struct hPALIst *mD5TailSent;
struct hPALIst *mD5HeadSent;

struct hPALIst *sHA1Conversion;
struct hPALIst *sHA1TailSent;
struct hPALIst *sHA1HeadSent;

struct hPALIst *sHA256Conversion;
struct hPALIst *sHA256TailSent;
struct hPALIst *sHA256HeadSent;

struct hPALIst *sHA512Conversion;
struct hPALIst *sHA512TailSent;
struct hPALIst *sHA512HeadSent;

sem_t megaFuckinLock; // Just meant for later. 
rwlock_t conversionLock;
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

void *getHashList(void *fileWithHashes){
	FILE *fp;
	char hexHash[2*KEEP + 1];
	fp = fopen((char *)fileWithHashes, "r");
	assert(fp != NULL);
	while(fscanf(fp, "%s", hexHash) == 1){
		numHashed++;
		struct cracked_hash *tempEnt = (struct cracked_hash *) malloc(sizeof(struct cracked_hash));
		strcpy(tempEnt->hash, hexHash); 
		tempEnt->alg = NULL;
		tempEnt->password = NULL;
		tailSentinel->entry = tempEnt; // The (usually) empty tailSentinel replaces the entry
		tailSentinel = tailSentinel->next; //tailSentinel is "incremented"
		tailSentinel->next = (struct hPAList *) malloc(sizeof(struct hPAList)); 
	}
    sem_post(&megaFuckinLock);
}

void *getPWordList(void *fileWithPWords){
	/* Any ideas commented in getHashList are basically the same here */
	FILE *fp;
	fp = fopen((char *)fileWithPWords, "r");
	assert(fp != NULL);
	char password[256];
	while(fscanf(fp, "%s", password) == 1){

        rwlock_acquire_writelock(&conversionLock);

		pTSent->password = strdup(password);
		pTSent = pTSent->next;
		pTSent->next = (struct pList *) malloc(sizeof(struct pList));
		strcpy(password, ""); //As a precaution, effectively clears password

        rwlock_release_writelock(&conversionLock);
		// for the next password entry. 

	}
    pTSent->next = NULL;
    sem_post(&megaFuckinLock);
}

void *mD5Convertor(void *pWord){
    struct pList *iter = pHSent;
    
    while(pTSent->next != NULL){

    }
}

void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
    sem_init(&megaFuckinLock, 0, 1);
    rwlock_init(&conversionLock);
    sem_wait(&megaFuckinLock);

    allHashes = (struct hPAList *) malloc(sizeof(struct hPAList));
	allHashes->next = (struct hPAList *) malloc(sizeof(struct hPAList));
	tailSentinel = allHashes;
	headSentinel = allHashes;

    allPWords = (struct pList *) malloc(sizeof(struct pList));
	allPWords->next = (struct pList *) malloc(sizeof(struct pList));
	pTSent = allPWords;
	pHSent = allPWords;

    pthread_t hashFinder;
    pthread_create(hashFinder, NULL, getHashList, hashed_list);

    pthread_t pwFinder;
    pthread_create(pwFinder, NULL, getPWordList, password_list);
    

    sem_wait(&megaFuckinLock);
}