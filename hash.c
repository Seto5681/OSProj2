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

/*3/28/2025, 6:03 PM:
NOT THE PRETTIEST CODE. 
I'll section off different parts of the program and explain. I'll label things in parts so that
it's easier to see a step-by-step thought process

Step 0, Research: 

	The original crack_hashed_passwords function can be generalized as such:

		0. Initialize a file pointer, 256-character password buffer, 33-character hash buffer,
		n_hashed to 0, a future list of cracked_hashes

		1. Iterate through the list of hashes to count the number of hashes available

		2. Rewind the file pointer. Call malloc on cracked_hashes to be a n_hashed-sized array. 
		Then, iterate through the file pointer in an i = 0 to n_hashed for loop, setting 
		cracked_hashes[i]'s information (setting password and alg to null and hash to the 
		current hash value seen by the file pointer)

		3. Reset the file pointer to the list of passwords. 

		4. Now, a rather large while loop that reads each password in our list of passwords into 
		a string. 
    		4a. For each hash algorithm, do(i iterations):
        			4aλ. Create the variable hash. hash will hold the string produced when hash algorithm
        			i receives the current password

        			4ai. Store in hexed_hash the hexadecimal representation of the current hash.Append it 
        			with '\0'

        			4aii. (j = 0 to n_hashed) For each known hash in cracked_hashes, if cracked_hashes[j].password
        			isn't null, then we've made a match already. Therefore, continue. If this value is null,
        			we'll check if cracked_hashes[j].hash is the same as hexed_hash. If so, we've made a match
        			and can store the algorithm and password. Otherwise, we test the next hash
        
		5. After iterating through the above, we print if any particular hash was seen in the list of passwords


I decided first that there would be 2 functions that could simultaneously run:
	1. A function to read each hash we must find a matching password-hashAlgorithm pair for from a file

	2. A function to read each password that we'll have to convert into 4 hashes, each. 

Thus getting me getHashList() and getPWordList(). Each have similar behavior and technically don't 
interract with one another, meaning there wasn't any kind of bounded buffer to worry about. 

I decided to then store each of these entries into linked lists for future printing. I therefore 
defined the structs pList (password list) and hPAList (hash-algorithm-password list).
The goal would be to, later on, iterate through these lists to find matches. 

Go ahead and jump to part 1 from here via control f
*/
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/*
Part 3. Locks

Since the password loader and 4 hash conversion functions were to run simultaenously, i decided
to implement the reader-writer lock, straight from the text book. Moving on to part 4
*/
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
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/* Part 1. Linked Lists 
	Since I decided that 2 functions would run simultaneously, I decided each could store its
information into their own structures without needing to repeatedly loop. Therefore, a linked
list of passwords and a linked list of cracked_hash entries. Moving on to part 2*/
struct pList {
	char *password;
	struct pList *next;
};

struct hPAList {
	struct cracked_hash *entry;
	struct hPAList *next;
};
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
int numHashed; //Number of hashes to check
/* Part 2. List Declarations
	Here, I made the linked lists previously mentioned. Now, by this point when I was first 
typing things up, I decided that maybe it was possible to make each hash algorithm its own thread,
and make 4 different linked lists. 

(6:21 PM, Idea: Maybe just run getHashList and getPWordList as 2 threads initially, then each of 
the algorithm finders AFTER but concurrently?)

	Each linked list would store some password, a specific algorithm name, and the appropriate
hash value from running that password through the named algorithm. Thus, there are 6 linked
lists here. Moving on to Part 3, above. 
*/
struct pList *pTSent; // pTSent for "passwordTailSentinel". Similar idea below
struct pList *pHSent; 
struct pList *allPWords;

struct hPAList *tailSentinel; 
struct hPAList *headSentinel;
struct hPAList *allHashes;

struct hPAList *mD5TailSent;
struct hPAList *mD5HeadSent;
struct hPAList *mD5Conversion;

struct hPAList *sHA1Conversion;
struct hPAList *sHA1TailSent;
struct hPAList *sHA1HeadSent;

struct hPAList *sHA256Conversion;
struct hPAList *sHA256TailSent;
struct hPAList *sHA256HeadSent;

struct hPAList *sHA512Conversion;
struct hPAList *sHA512TailSent;
struct hPAList *sHA512HeadSent;

sem_t megaFuckinLock; // Just meant for later. 
sem_t entryStatus[4];
rwlock_t conversionLock; 
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/* Part 4. Function explanations
I'm gonna discuss each function separately. 
Starting in the original function of initializeAllGlobals (part 4a.) */
void *getHashList(void *fileWithHashes){
	FILE *fp;
	char hexHash[2*KEEP + 1];
	fp = fopen((char *)fileWithHashes, "r");
	/* First, open the file with the list of hashes */
	assert(fp != NULL);
	while(fscanf(fp, "%s", hexHash) == 1){
		numHashed++;
		tailSentinel = tailSentinel->next; //tailSentinel is "incremented"
		struct cracked_hash *tempEnt = (struct cracked_hash *) malloc(sizeof(struct cracked_hash));
		strcpy(tempEnt->hash, hexHash); 
		// A hash entry is stored
		tempEnt->alg = NULL;
		tempEnt->password = NULL;
		// Just in case, NULL setting!
		tailSentinel->entry = tempEnt; // Fill out the tail sentinel's entry
		tailSentinel->next = (struct hPAList *) malloc(sizeof(struct hPAList)); // Pre-allocate for the next val
	}
	free(tailSentinel->next); 
    sem_post(&megaFuckinLock); //Return lock to cracked_hashed_passwords
}

void *getPWordList(void *fileWithPWords){
	FILE *fp;
	fp = fopen((char *)fileWithPWords, "r");
	assert(fp != NULL);
	char password[256];
	while(fscanf(fp, "%s", password) == 1){
		/* The primary difference here is the use of the locks below */
        rwlock_acquire_writelock(&conversionLock);
		printf("%s", password);
		pTSent->password = strdup(password);
		strcpy(password, ""); //As a precaution, effectively clears password
		pTSent = pTSent->next;
		pTSent->next = (struct pList *) malloc(sizeof(struct pList));

		/* Each time the function notes that a password was stored, it signals the hash convertors
		that 1 new password is available and gives up the writers lock */
		sem_post(&entryStatus[0]);
		sem_post(&entryStatus[1]);
		sem_post(&entryStatus[2]);
		sem_post(&entryStatus[3]);
        rwlock_release_writelock(&conversionLock);
		// for the next password entry. 

	}
    free(pTSent->next);
    sem_post(&megaFuckinLock);
}

/* Part 4b. 
Each of the convertors works under the same idea, different names
*/

void *mD5Convertor(void *pWord){
    struct pList *iter0 = pHSent; //Look at the first password known
	char hex_hash[2*KEEP+1]; //For cuture
	/* The linked list filler */
	while(pTSent->next != NULL){
		rwlock_acquire_readlock(&conversionLock); //First, check if the writer is NOT currently writing
		sem_wait(&entryStatus[0]); // Then, check if there's anything to read
		// I think the layering of these locks is a problem? I don't know yet

		unsigned char *md5Hash = fn[0]((unsigned char *)iter0->password, strlen(iter0->password));
		/* Convert whatever password iter0 sees into a hash, store each of the password, algorithm used,
		and resultant hash into the linked list of mD5 conversions */ 
		for(int i = 0; i < KEEP; i++){
			sprintf(&mD5TailSent->entry->hash[i], "%02x", md5Hash[i]);
		}
		mD5TailSent->entry->hash[2 * KEEP] = '\0';  //Append the hash with a null char

		mD5TailSent->entry->password = strdup(iter0->password); // Store the password read
		mD5TailSent->entry->alg = strdup(algs[0]); // Store the name of the hash algorithm used
		mD5TailSent = mD5TailSent->next; // Move the tail sentinel over for future use
		mD5TailSent->next = (struct hPAList *) malloc(sizeof( struct hPAList)); // pre-allocate
		free(md5Hash); //free, just in case
		rwlock_release_readlock(&conversionLock); // give up the readers lock
	}
	free(mD5TailSent->next); // Since the tailsentinels->next end up having pre-allocated memory, free that memory
	
}

void *sHA1Convertor (void *pWord){
	struct pList *iter1 = pHSent;
	while(pTSent->next != NULL){
		rwlock_acquire_readlock(&conversionLock);
		sem_wait(&entryStatus[1]);

		unsigned char *s1Hash = fn[1]((unsigned char *)iter1->password, strlen(iter1->password));

		for(int j = 0; j < KEEP; j++){
			sprintf(&sHA1TailSent->entry->hash[j], "%02x", s1Hash[j]);
		}
		sHA1Conversion->entry->hash[2 * KEEP] = '\0';

		sHA1TailSent->entry->password = strdup(iter1->password);
		sHA1TailSent->entry->alg = strdup(algs[1]);
		sHA1TailSent = sHA1TailSent->next;
		sHA1TailSent->next = (struct hPAList *) malloc(sizeof(struct hPAList));
		free(s1Hash);
		rwlock_release_readlock(&conversionLock);
	}
	free(sHA1TailSent->next);
}

void *sHA256Convertor (void *pWord){
	struct pList *iter2 = pHSent;
	while(pTSent->next != NULL){
		rwlock_acquire_readlock(&conversionLock);
		sem_wait(&entryStatus[2]);

		unsigned char *s256Hash = fn[2]((unsigned char *)iter2->password, strlen(iter2->password));
		for(int j = 0; j < KEEP; j++){
			sprintf(&sHA256TailSent->entry->hash[j], "%02x", s256Hash[j]);
		}
		sHA256Conversion->entry->hash[2 * KEEP] = '\0';

		sHA256TailSent->entry->password = strdup(iter2->password);
		sHA256TailSent->entry->alg = strdup(algs[2]);
		sHA256TailSent = sHA256TailSent->next;
		sHA256TailSent->next = (struct hPAList *) malloc(sizeof(struct hPAList));
		free(s256Hash);
		rwlock_release_readlock(&conversionLock);
	}
}

void *sHA512Convertor (void *pWord){
	struct pList *iter3 = pHSent;
	while(pTSent->next != NULL){
		rwlock_acquire_readlock(&conversionLock);
		sem_wait(&entryStatus[3]);

		unsigned char *s512Hash = fn[3]((unsigned char *)iter3->password, strlen(iter3->password));
		for(int j = 0; j < KEEP; j++){
			sprintf(&sHA512TailSent->entry->hash[j], "%02x", s512Hash[j]);
		}
		sHA512Conversion->entry->hash[2 * KEEP] = '\0';

		sHA512TailSent->entry->password = strdup(iter3->password);
		sHA512TailSent->entry->alg = strdup(algs[3]);
		sHA512TailSent = sHA512TailSent->next;
		sHA512TailSent->next = (struct hPAList *) malloc(sizeof(struct hPAList));

		rwlock_release_readlock(&conversionLock);
		free(s512Hash);
	}
	free(sHA512TailSent->next);
}

void initializeAllGlobals(){
/* Part 4a.
By now, I know I had 4 threads that would read from a common bounded buffer, 1 thread that would be produced and read
from over time, and 1 thread that would have little interractions with the others. Therefore, entryStatus (an array
of 4 locks), conversionLock, and megaFuckinLock was made. 

I wanted to make it so that conversion lock, the reader-writer lock, would ensure that each of the threads that would 
read from the list of passwords would read ONLY to the point where the linked list of passwords ended until the password
reader was done. 
Adding upon the idea of forcing the hash function threads to only read to a certain point, each were forced to lock
whenever they had access to no new elements while the password reader was running, and only the password reader could
wake them up. The readers would check if they were allowed to read or if there was anything to read, the writer would
inform them when this happened.

And megaFuckinLock was just to force all threads to finish before checking if the program is running correctly for debugging
(spoiler alert its not my bad)

Now here, each lock and linked list is initialized and the linked list sentinels receive "pre-allocations" 
*/
	sem_init(&entryStatus[0], 0, 0);
	sem_init(&entryStatus[1], 0, 0);
	sem_init(&entryStatus[2], 0, 0);
	sem_init(&entryStatus[3], 0, 0);
	rwlock_init(&conversionLock);

	sem_init(&megaFuckinLock, 0, 1);
    sem_wait(&megaFuckinLock);

	allHashes = (struct hPAList *) malloc(sizeof(struct hPAList));
	allHashes->next = (struct hPAList *) malloc(sizeof(struct hPAList));
	allHashes->entry = NULL;
	tailSentinel = allHashes;
	headSentinel = allHashes;

	mD5Conversion = (struct hPAList *) malloc(sizeof(struct hPAList));
	mD5Conversion->next = (struct hPAList *) malloc(sizeof(struct hPAList));
	mD5HeadSent = mD5Conversion;
	mD5TailSent = mD5Conversion;

	allPWords = (struct pList *) malloc(sizeof(struct pList));
	allPWords->next = (struct pList *) malloc(sizeof(struct pList));
	pTSent = allPWords;
	pHSent = allPWords;

	sHA1Conversion = (struct hPAList *) malloc(sizeof(struct hPAList));
	sHA1Conversion->next = (struct hPAList *) malloc(sizeof(struct hPAList));
	sHA1HeadSent = sHA1Conversion;
	sHA1TailSent = sHA1Conversion;

	sHA256Conversion = (struct hPAList *) malloc(sizeof(struct hPAList));
	sHA256Conversion->next = (struct hPAList *) malloc(sizeof(struct hPAList));
	sHA256HeadSent = sHA256Conversion;
	sHA256TailSent = sHA256Conversion;

	sHA512Conversion = (struct hPAList *) malloc(sizeof(struct hPAList));
	sHA512Conversion->next = (struct hPAList *) malloc(sizeof(struct hPAList));
	sHA512HeadSent = sHA512Conversion;
	sHA512TailSent = sHA512Conversion;
}

void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
	initializeAllGlobals();

    pthread_t hashFinder;
    pthread_create(&hashFinder, NULL, getHashList, hashed_list);

    pthread_t pwFinder;
    pthread_create(&pwFinder, NULL, getPWordList, password_list);

	pthread_t md5Finder;
	pthread_create(&md5Finder, NULL, mD5Convertor, NULL);

	pthread_t sha1Finder;
	pthread_create(&sha1Finder, NULL, sHA1Convertor, NULL);

	pthread_t sha256Finder;
	pthread_create(&sha256Finder, NULL, sHA256Convertor, NULL);

	pthread_t sha512Finder;
	pthread_create(&sha512Finder, NULL, sHA512Convertor, NULL);

    sem_wait(&megaFuckinLock);

	/* Part 5. (above) Starts the threads and waits for them to finish!
	Below: Intended to check for correctness. I have fucked something up EGREGIOUSLY, don't know what
	at this moment (3/28/2025 6:46 PM), but I'll get to it soon!!!!! */
	while(pHSent != NULL){
		struct pList *temp = pHSent;
		pHSent = pHSent->next;
		temp->next = NULL;
		free(temp->password);
		free(temp);
	}
	struct hPAList *hashIter = headSentinel;
	FILE *fp;
	fp = fopen(output, "w");
	assert(fp != NULL);
	while(hashIter != NULL){
		/* This loop is most DEFINITELY NOT SETUP WELL. By the time I started working on this, my brain had a lot 
		of fatigue and uhhhhh I just wasn't thinking through that well. */
		if((strcmp(sHA512HeadSent->entry->hash, hashIter->entry->hash) == 0) && (hashIter->entry->password == NULL)){
			hashIter->entry->password = strdup(sHA512HeadSent->entry->password);
		}
		struct hPAList *temp3 = sHA512HeadSent;
		sHA512HeadSent = sHA512HeadSent->next;
		temp3->next = NULL;
		free(temp3->entry->alg);
		free(temp3->entry->password);
		free(temp3->entry->hash);
		free(temp3->entry);
		//free(temp->next);
		free(temp3);

		if((strcmp(sHA256HeadSent->entry->hash, hashIter->entry->hash) == 0) && (hashIter->entry->password == NULL)){
			hashIter->entry->password = strdup(sHA256HeadSent->entry->password);
		}
		struct hPAList *temp2 = sHA256HeadSent;
		sHA256HeadSent = sHA256HeadSent->next;
		temp2->next = NULL;
		free(temp2->entry->alg);
		free(temp2->entry->password);
		free(temp2->entry->hash);
		free(temp2->entry);
		//free(temp->next);
		free(temp2);


		if((strcmp(sHA1HeadSent->entry->hash, hashIter->entry->hash) == 0) && (hashIter->entry->password == NULL)){
			hashIter->entry->password = strdup(sHA1HeadSent->entry->password);
		}
		struct hPAList *temp1 = sHA1HeadSent;
		sHA1HeadSent = sHA1HeadSent->next;
		temp1->next = NULL;
		free(temp1->entry->alg);
		free(temp1->entry->password);
		free(temp1->entry->hash);
		free(temp1->entry);
		//free(temp->next);
		free(temp1);

		if((strcmp(mD5HeadSent->entry->hash, hashIter->entry->hash) == 0) && (hashIter->entry->password == NULL)){
			hashIter->entry->password = strdup(mD5HeadSent->entry->password);
		}
		struct hPAList *temp = mD5HeadSent;
		mD5HeadSent = mD5HeadSent->next;
		temp->next = NULL;
		free(temp->entry->alg);
		free(temp->entry->hash);
		free(temp->entry->password);
		free(temp);

		if(hashIter->entry->password == NULL){
			fprintf(fp, "not found\n");
		} else {
			fprintf(fp, "%s:%s\n", hashIter->entry->password, hashIter->entry->alg);
		}

		struct hPAList *finalTemp = hashIter;
		hashIter = hashIter->next;
		finalTemp->next = NULL;
		free(finalTemp->entry->alg);
		free(finalTemp->entry->hash);
		free(finalTemp->entry->password);
		free(finalTemp);
	}
	while(mD5HeadSent != NULL){
		struct hPAList *temp = mD5HeadSent;
		mD5HeadSent = mD5HeadSent->next;
		temp->next = NULL;
		free(temp->entry->alg);
		free(temp->entry->hash);
		free(temp->entry->password);
		free(temp);
	}
	while(sHA1HeadSent != NULL){
		struct hPAList *temp1 = sHA1HeadSent;
		sHA1HeadSent = sHA1HeadSent->next;
		temp1->next = NULL;
		free(temp1->entry->alg);
		free(temp1->entry->password);
		free(temp1->entry->hash);
		free(temp1->entry);
		//free(temp->next);
		free(temp1);
	}
	while(sHA256HeadSent != NULL){
		struct hPAList *temp2 = sHA256HeadSent;
		sHA256HeadSent = sHA256HeadSent->next;
		temp2->next = NULL;
		free(temp2->entry->alg);
		free(temp2->entry->password);
		free(temp2->entry->hash);
		free(temp2->entry);
		//free(temp->next);
		free(temp2);
	}
	while(sHA512HeadSent != NULL){
		struct hPAList *temp3 = sHA512HeadSent;
		sHA512HeadSent = sHA512HeadSent->next;
		temp3->next = NULL;
		free(temp3->entry->alg);
		free(temp3->entry->password);
		free(temp3->entry->hash);
		free(temp3->entry);
		//free(temp->next);
		free(temp3);
	}
}