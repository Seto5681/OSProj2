// Multithreaded version of crack_hashed_passwords()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "hash_functions.h"

#define KEEP 16
#define MAX_PASSWORDS 10000000
#define NUM_THREADS 6

#define HASH_TABLE_SIZE 100003  // A prime number


struct node {
    char* key;
    char* password;
    char* alg;
    struct node* next;
};
 

void setNode(struct node* node, char* key, char* value1, char* value2)
{
    node->key = key;
    node->password = value1;
    node->alg = value2;
    node->next = NULL;
    return;
};
 
struct hashMap {
    int numOfElements, capacity;
    struct node** arr;
};
 

void initializeHashMap(struct hashMap* mp, int cap)
{
    mp->capacity = cap;
    mp->numOfElements = 0;
    mp->arr = (struct node**)malloc(sizeof(struct node*)* mp->capacity);
    return;
}
 
int hashFunction(struct hashMap* mp, char* key)
{
    int bucketIndex;
    int sum = 0, factor = 31;
    for (int i = 0; i < strlen(key); i++) {

        sum = ((sum % mp->capacity)
               + (((int)key[i]) * factor) % mp->capacity)
              % mp->capacity;

        factor = ((factor % __INT16_MAX__)
                  * (31 % __INT16_MAX__))
                 % __INT16_MAX__;
    }
    bucketIndex = sum;
    return bucketIndex;
}
 
void insert(struct hashMap* mp, char* key)
{
    int bucketIndex = hashFunction(mp, key);
    struct node* newNode = (struct node*)malloc(sizeof(struct node));

    setNode(newNode, key, NULL, NULL);
 

    if (mp->arr[bucketIndex] == NULL) {
        mp->arr[bucketIndex] = newNode;
    }
 
    else {
        newNode->next = mp->arr[bucketIndex];
        mp->arr[bucketIndex] = newNode;
    }
    return;
}
 
 
struct node* search(struct hashMap* mp, char* key)
{
    int bucketIndex = hashFunction(mp, key);
    struct node* bucketHead = mp->arr[bucketIndex];
    while (bucketHead != NULL) {
        if (strcmp(bucketHead->key, key) == 0) {
            return bucketHead;  // Found match
        }
        bucketHead = bucketHead->next;
    }
    return NULL;  // Not found
}

struct hashMap *mp;

struct cracked_hash {
    char hash[2 * KEEP + 1];
    char *password, *alg;
};

typedef unsigned char *(*hashing)(unsigned char *, unsigned int);

int n_algs = 4;
hashing fn[4] = {calculate_md5, calculate_sha1, calculate_sha256, calculate_sha512};
char *algs[4] = {"MD5", "SHA1", "SHA256", "SHA512"};

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

struct cracked_hash *cracked_hashes;
int n_hashed = 0;
char **passwords;
int n_passwords = 0;

int compare_hashes(char *a, char *b) {
    for (int i = 0; i < 2 * KEEP; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

void *worker(void *arg) {
    long tid = (long)arg;
    char hex_hash[2 * KEEP + 1];

    for (int idx = tid; idx < n_passwords; idx += NUM_THREADS) {
        char *password = passwords[idx];
        for (int i = 0; i < n_algs; i++) {
            unsigned char *hash = fn[i]((unsigned char *)password, strlen(password));
            for (int j = 0; j < KEEP; j++)
                sprintf(&hex_hash[2 * j], "%02x", hash[j]);
            hex_hash[2 * KEEP] = '\0';
            
            struct node* found = search(mp, hex_hash);
            if (found != NULL && found->password == NULL){
                pthread_mutex_lock(&lock);
                if (found->password == NULL){
                    found->password = strdup(password);
                    found->alg = algs[i];
                }
                pthread_mutex_unlock(&lock);
            }
            
            free(hash);
        }
    }
    return NULL;
}

void crack_hashed_passwords(char *password_list, char *hashed_list, char *output) {
    FILE *fp;
    char line[256];

    // Load hashed passwords
    fp = fopen(hashed_list, "r");
    assert(fp != NULL);
    while (fscanf(fp, "%s", line) == 1) n_hashed++;
    rewind(fp);
    cracked_hashes = malloc(n_hashed * sizeof(struct cracked_hash));
    for (int i = 0; i < n_hashed; i++) {
        fscanf(fp, "%s", cracked_hashes[i].hash);
        cracked_hashes[i].password = NULL;
        cracked_hashes[i].alg = NULL;
    }
    fclose(fp);

    //load the hashes into a map for faster lookup
    mp= (struct hashMap*)malloc(sizeof(struct hashMap));
    initializeHashMap(mp, 5000);
    for(int i = 0; i < n_hashed; i++){
        insert(mp, cracked_hashes[i].hash);
    }

    // Load passwords into array
    passwords = malloc(MAX_PASSWORDS * sizeof(char *));
    fp = fopen(password_list, "r");
    assert(fp != NULL);
    while (fscanf(fp, "%s", line) == 1) {
        passwords[n_passwords++] = strdup(line);
    }
    fclose(fp);

    // Create worker threads
    pthread_t threads[NUM_THREADS];
    for (long i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, worker, (void *)i);
    }
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    struct node* curnode;
    for(int i = 0; i < n_hashed; i++){
        curnode = search(mp, cracked_hashes[i].hash);
        cracked_hashes[i].password = curnode->password;
        cracked_hashes[i].alg = curnode->alg;
    }

    // Output
    fp = fopen(output, "w");
    for (int i = 0; i < n_hashed; i++) {
        if (cracked_hashes[i].password == NULL)
            fprintf(fp, "not found\n");
        else
            fprintf(fp, "%s:%s\n", cracked_hashes[i].password, cracked_hashes[i].alg);
    }
    fclose(fp);

    // Free
    for (int i = 0; i < n_hashed; i++)
        free(cracked_hashes[i].password);
    free(cracked_hashes);
    for (int i = 0; i < n_passwords; i++)
        free(passwords[i]);
    free(passwords);
}
