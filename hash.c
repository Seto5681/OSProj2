#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "hash_functions.h"

#define KEEP 16 // only the first 16 bytes of a hash are kept

// A character variable holds 1 byte. Thereforce, cracked_hash 
// holds 33 bytes or 33 characters
struct cracked_hash {
	char hash[2*KEEP+1];
	char *password, *alg;
};

typedef unsigned char * (*hashing)(unsigned char *, unsigned int);
int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"}; // Names of hash functions used
// (hashing)-type variables are, essentially, function pointers.

/*
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

I identify a few things that the function could split across a few threads.
1. The loop intended to obtain the list of passwords and the loop intended to obtain the list of hashes
was split into 2 functions: getHashList and getPasswordList. These 2 processes, so long as the input
files are NOT the same, could run concurrently. 
Thus, we get threads 1 and 2. Each thread writes into the global buffers allHashes and allPasswords

The struct hPAList is meant to mean "hex-Password-Algorithm list". In the first loop of the original 
crack_hashed_passwords function, we would iterate through the list of n hashes, allocate an n-element
array, THEN RE-ITERATE through the same file again. Instead of having 2 loops, here, I use a linked 
list using sentinels so that each time a hash is read, it is read into the list list as a part of 
a cracked_hash structure. 

Similarly, pList is another linked list, instead only containing passwords. It has its own set of 
head and tail sentinels and such and is filled concurrently as the allValues structured is too. 
*/

/* Also, any variable defintions/struct creations that were in the original file are all going to 
remain in the top most section. Any custom structures will be in the section below*/


struct pList {
	char *password;
	struct pList *next;
};

struct pList *pTSent; // pTSent for "passwordTailSentinel". Similar idea below
struct pList *pHSent; 
struct pList *allPWords;

int numHashed; //Number of hashes to check
struct hPAList {
	struct cracked_hash *entry;
	struct hPAList *next;
};

struct hPAList *tailSentinel; 
struct hPAList *headSentinel;
struct hPAList *allHashes;


void *getHashList(char *fileWithHashes){
	/* When given the path to a file with the list of hashes, this function opens that file, reads each
	hash seen and copies it into a linked list */

	FILE *fp;
	char hexHash[2*KEEP + 1];
	fp = fopen(fileWithHashes, "r");
	assert(fp != NULL);
	// The above  simply opens the hash .txt file

	allHashes = (struct hPAList *) malloc(sizeof(struct hPAList));
	allHashes->next = (struct hPAList *) malloc(sizeof(struct hPAList));
	tailSentinel = allHashes;
	headSentinel = allHashes;
	/* (Above) Here, the linked lists and sentinels that will be used to store hashes are initialized. 
	Currently unsure if this SHOULD have a lock but I feel like it does. The tailSentinel is intended
	to always look at the end of the linked list so that any hashes inserted into it is simply "dropped"
	at the end of all vals. */
	while(fscanf(fp, "%s", hexHash) == 1){
		numHashed++;
		struct cracked_hash *tempEnt = (struct cracked_hash *) malloc(sizeof(struct cracked_hash));
		// In some temporary cracked_hash pointer, allocate memory

		strcpy(tempEnt->hash, hexHash); 
		tempEnt->alg = NULL;
		tempEnt->password = NULL;
		// In the dynamically allocated tempEnt, copy whatever hash string was last read and
		// set the corresponding password and alg field to null

		// Now to connect the new entry to the linked list
		tailSentinel->entry = tempEnt; // The (usually) empty tailSentinel replaces the entry
		// value to look at whereever tempEnt was looking at

		tailSentinel = tailSentinel->next; //tailSentinel is "incremented"

		tailSentinel->next = (struct hPAList *) malloc(sizeof(struct hPAList)); 
		//pre-allocate memory at wherever tailSentinel currently looks
	}
	// The entire loop above SHOULD be locked during runtime via a global semaphore
	// This semaphore will be named hListProt or hLP (for hashList protection)
}

void *getPWordList(char *fileWithPWords){
	/* Any ideas commented in getHashList are basically the same here */
	FILE *fp;
	fp = fopen(fileWithPWords, "r");
	assert(fp != NULL);

	char password[256];

	allPWords = (struct pList *) malloc(sizeof(struct pList));
	allPWords->next = (struct pList *) malloc(sizeof(struct pList));
	pTSent = allPWords;
	pHSent = allPWords;
	// The 4 lines above are just linked list initialization
	// Probably needs a lock. Same for the while loop below

	while(fscanf(fp, "%s", password) == 1){
		pTSent->password = strdup(password);
		pTSent = pTSent->next;
		pTSent->next = (struct pList *) malloc(sizeof(struct pList));
		strcpy(password, ""); //As a precaution, effectively clears password
		// for the next password entry. 
	}
}

/* My goal with separating the crack_hashed_passwords function in the manner that I am doing 
is that I want to do multiple things at the same time: Find passwords that need to be checked 
and which hashes are to be checked in the first place as seen above. But (as of 3/27/2025 at 5:11 PM)
the crack_hashed_passwords function ALSO needs to convert each password to 1 of 4 encryption methods
and compares each of them against the list of hashes. 

In the end, I aim to emulate the producer-consumer problem where certain functions are both producers
AND consumers. 
*/

// Function name: crack_hashed_passwords
// Description:   Computes different hashes for each password in the password list,
//                then compare them to the hashed passwords to decide whether if
//                any of them matches this password. When multiple passwords match
//                the same hash, only the first one in the list is printed.
/* hash.h simply declares the password below.  */
void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
	FILE *fp;
	char password[256];  // passwords have at most 255 characters
	char hex_hash[2*KEEP+1]; // hashed passwords have at most 'keep' characters

	// load hashed passwords
	int n_hashed = 0;
	struct cracked_hash *cracked_hashes;
	fp = fopen(hashed_list, "r");
	assert(fp != NULL); 
	// Just the file!


	while(fscanf(fp, "%s", hex_hash) == 1){
		// n_hashed is the number of hashed passwords. Reminder: fscanf reads line-by-line
		n_hashed++;
	}
	rewind(fp); 

	/* Above, we rewind the hashed_list file pointer. Then, we create an array of cracked_hash's. 
	Since we have n_hashed passwords to consider, we allocate that many cracked_hash's entries and 
	fill the hash member of each under the fscanf */
	cracked_hashes = (struct cracked_hash *) malloc(n_hashed*sizeof(struct cracked_hash));
	assert(cracked_hashes != NULL);
	for(int i=0; i < n_hashed; i++) {
		fscanf(fp, "%s", cracked_hashes[i].hash);
		cracked_hashes[i].password = NULL;
		cracked_hashes[i].alg = NULL;
	}
	fclose(fp);

	// load common passwords, hash them, and compare them to hashed passwords
	fp = fopen(password_list, "r"); //Now we open the password list
	assert(fp != NULL);
	while(fscanf(fp, "%s", password) == 1) {
		for(int i=0; i < n_algs; i++) {
			/*Now, we wish to find the hash of each password password with the set up below*/
			unsigned char *hash = fn[i]((unsigned char *)password, strlen(password));
			for(int j=0; j < KEEP; j++){
				/* Once the hash of a password is obtained, hex_hash receives the hexadecimal form 
				of that password. We only care for the first 16 bytes. Since we store the hash as a 
				hexadecimal and each HD digit is already 4 bits, we use [2*j] to account for the 
				8-bit, 2-digit hexadeximal number*/
				sprintf(&hex_hash[2*j], "%02x", hash[j]);
			}
			hex_hash[2*KEEP] = '\0'; //Append the null character. 
			for(int j=0; j < n_hashed; j++) {

				/*If a cracked_hashes entry is null, that means we haven't found the password-encryption 
				combination that yields a particular hash. If a comparison for a hash formed with algorithm
				j and hash[j] is true, then we found the algorithm for a passowrd. */
				if(cracked_hashes[j].password !=  NULL)
					continue;
				if(compare_hashes(hex_hash, cracked_hashes[j].hash)) {
					cracked_hashes[j].password = strdup(password);
					cracked_hashes[j].alg = algs[i];
					break;
				}
			}
			free(hash);
		}
	}
	fclose(fp);

	// print results
	fp = fopen(output, "w");
	assert(fp != NULL);
	for(int i=0; i < n_hashed; i++) {
		if(cracked_hashes[i].password ==  NULL)
			fprintf(fp, "not found\n");
		else
			fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
	}
	fclose(fp);

	// release stuff
	// Keeping this function here
	for(int i=0; i < n_hashed; i++)
		free(cracked_hashes[i].password);
	free(cracked_hashes);
}

int compare_hashes(char *a, char *b) {
	/* Once any 2  */
	// The only edit done here was adding brackets to each of the if and for statements
	// to make reading easier
	for(int i=0; i < 2*KEEP; i++) {
		if(a[i] != b[i]){
			return 0;
		}
	}
	return 1;
}