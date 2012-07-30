#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define HELPMENUSHORT ("[-h] -l LENGTH [-c CHARSET] [-p PARTIAL] [--file FILELOCATION] [--hash HASH] [-r] [--no-screen] [--debug] \n")
#define HELPMENULONG ("A program to output possible combinations in a character set with a given \n\
length \n\
 \n\
optional arguments: \n\
  -h, --help            show this help message and exit \n\
  -l LENGTH, --length LENGTH \n\
                        length of combination strings, total including partial \n\
  -c CHARSET, --charset CHARSET \n\
                        A list of valid characters \n\
  -p PARTIAL, --partial PARTIAL \n\
                        A partial beginning to the whole string. \n\
  --file FILELOCATION   Location to output combinations \n\
  --hash HASH           SHA1 and MD5 \n\
  -r, --resume          To resume a previous session (not implemented yet) \n\
  --no-screen           Dont print to the screen \n\
  --debug               Show some debug output\n")

int debug = 0;
int quiet = 0;
int hashNum = 0;
int printToFile = 0;
FILE *fp;
//hash[0] = '0';

void createCombinations(char *, char *, int, char *);
void createHash(char *, char *);

void append(char * s, char c) {
	int len = strlen(s);
    s[len] = c;
    s[len+1] = '\0';
}

int main(int argc, char *argv[]) {
	int i;
	int returnCode = 0;
	char partial[50] = "";
	unsigned int desiredLen = 5;
	char chars[150] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	char fileLocation[150];
	fileLocation[0] = '0';

	// check for arguments
	if (argc < 2) {printf("Usage: %s %s", argv[0], HELPMENUSHORT); return 1;}

	for(i = 0; i < argc; i++) {
		if (strncmp(argv[i], "--debug", 7) == 0 || strncmp(argv[i], "-d", 3) == 0) {
			debug = 1;
			printf("Debug turned on\n");
		}
	}

	// Parse Args
	for(i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			printf("Usage: %s %s", argv[0], HELPMENULONG);
			return 0;
		}
		else if (strcmp(argv[i], "--length") == 0 || strcmp(argv[i], "-l") == 0) {
			i++;
			desiredLen = atoi(argv[i]);
			if (debug)
				printf("Set desired length to %d\nb", desiredLen);
			if(desiredLen > 50 ) {
				printf("Length is too long length must be lest then 50.\n");
				return 1;
			}
			if (desiredLen == 0) {
				printf("Invalid Length\n");
				return 1;
			}
			if (debug == 1)
				printf("Setting length to %d\n", debug);
		}
		else if (strcmp(argv[i], "--charset") == 0 || strcmp(argv[i], "-c") == 0) {
			i++;
			strncpy(chars, argv[i], sizeof(chars)-1);
			if (debug == 1)
					printf("Setting charset to %s", chars);
		}
		else if (strcmp(argv[i], "--partial") == 0 || strcmp(argv[i], "-p") == 0) {
			i++;
			if ( sizeof(argv[i]) > desiredLen) {
				printf("Error: Partial password length is greater then the final langth\n");
				return 1;
			}
			strncpy(partial, argv[i], sizeof(partial));
			if (debug == 1)
				printf("Setting Partial to %s\n", partial);
		}
		else if (strcmp(argv[i], "--file") == 0) {
			i++;
			if (argv[i] != 0) {
				if (debug == 1) {printf("Opening file %s\n", argv[i]);}
				fp=fopen(argv[i], "w");
				if (fp == 0) {
					printf("Unable to open file?\n");
					return 1;
				}
				else if ( debug == 1 ) {printf("File successfully opened\n");}
				if(strlen(argv[i]) < 150){
					strncpy(fileLocation, argv[i], 149);
					printToFile = 1;
				}
				else {printf("File location too long.\n");}
				fclose(fp);
			}
			else {
				printf("Need file name!\n");
			}
		}
		else if (strcmp(argv[i], "--no-screen") == 0){quiet = 1;}
		else if (strcmp(argv[i], "--hash") == 0) {
			i++;
			if (strcmp(argv[i], "md5") == 0) {hashNum = 1;}
			else if (strcmp(argv[i],"sha1") == 0 )
				hashNum = 2;
			else if (strcmp(argv[i], "sha224") == 0)
				hashNum = 3;
			else if (strcmp(argv[i], "sha256") == 0)
				hashNum = 4;
			else if (strcmp(argv[i], "sha384") == 0)
				hashNum = 5;
			else if (strcmp(argv[i], "sha512") == 0)
				hashNum = 6;
			else {
				printf("hash type not surported\n");
				printf("supported types: md5 sha1 sha224 sha256 sha384 sha512\n");
				exit(1);
			}
		}
	}
	createCombinations(chars, partial, desiredLen, fileLocation);
	return returnCode;
}

void createCombinations(char chars[150], char inputText[100], int desiredLen, char fileLocation[150]) {
	char compiledText[150] = "";
	int i = 0;
    const int length = strlen(chars);
	for(i = 0; i < length; i++) {
		strncpy(compiledText, inputText, desiredLen);
		append(compiledText, chars[i]);
		if ( strlen(compiledText) == desiredLen){
			//printf("hashNum: %d\n", hashNum);
			if(hashNum){
				createHash(compiledText, fileLocation);
			}
			else if (!quiet) {
				printf(compiledText);
				printf("\n");
			}
		}
		if ( strlen(compiledText) != desiredLen) {
			createCombinations(chars, compiledText, desiredLen, fileLocation);
		}
	}
}

void createHash(char hashInput[50], char fileLocation[150]) {
	int i;
	EVP_MD_CTX mdctx;
	unsigned char d[64];
    unsigned int md_len;
    switch (hashNum) {
    	case 1: EVP_DigestInit( &mdctx, EVP_md5() );
    	break;
    	case 2:EVP_DigestInit( &mdctx, EVP_sha1() );
    	break;
    	case 3:EVP_DigestInit( &mdctx, EVP_sha224() );
    	break;
    	case 4:EVP_DigestInit( &mdctx, EVP_sha256() );
    	break;
    	case 5:EVP_DigestInit( &mdctx, EVP_sha384() );
    	break;
    	case 6:EVP_DigestInit( &mdctx, EVP_sha512() );
    	break;
    }
    EVP_DigestUpdate( &mdctx, hashInput, strlen(hashInput) );
    EVP_DigestFinal_ex( &mdctx, d, &md_len );
    EVP_MD_CTX_cleanup( &mdctx );

    if (quiet != 1) {printf("text: %s, hash: ", hashInput);}
    if (printToFile == 1) { fp = fopen(fileLocation, "a");}
    for (i = 0; i < md_len; i++) {
    	if (quiet != 1) {
        	printf("%02x", d[i]);
    	}
    	if (printToFile == 1) {
    		fprintf(fp, "%02x", d[i]);
    	}
    }
    if (quiet != 1) {printf("\n");}
    if (printToFile == 1) {fprintf(fp, " %s\n", hashInput);;fclose(fp);}
}
