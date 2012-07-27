/* playing with memory */

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

void createCompinations(char *, char *, int, char *);
void createSHA1Hash(char *, char *);
void createSHA224Hash(char *, char *);
void createSHA256Hash(char *, char *);
void createSHA384Hash(char *, char *);
void createSHA512Hash(char *, char *);
void createMD5Hash(char *, char *);

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
				if (debug == 1) {
					printf("Opening file %s\n", argv[i]);
				}
				fp=fopen(argv[i], "w");
				if (fp == 0) {
					printf("Unable to open file?\n");
					return 1;
				}
				else if ( debug == 1 ) {
					printf("File successfully opened\n");
				}
				if(strlen(argv[i]) < 150){
					strncpy(fileLocation, argv[i], 149);
					printToFile = 1;
				}
				else {
					printf("File location too long.\n");
				}
				fclose(fp);
			}
			else {
				printf("Need file name!\n");
			}
		}
		else if (strcmp(argv[i], "--no-screen") == 0){
			quiet = 1;
		}
		else if (strcmp(argv[i], "--hash") == 0) {
			i++;
			if (strcmp(argv[i], "md5") == 0) {
				//printf("setting hash to md5\n");
				hashNum = 1;
			}
			else if (strcmp(argv[i],"sha1") == 0 ) {
				hashNum = 2;
			}
			else if (strcmp(argv[i], "sha224") == 0) {
				hashNum = 3;
			}
			else if (strcmp(argv[i], "sha256") == 0) {
				hashNum = 4;
			}
			else if (strcmp(argv[i], "sha384") == 0) {
				hashNum = 5;
			}
			else if (strcmp(argv[i], "sha512") == 0) {
				hashNum = 6;
			}
			else {
				printf("hash type not surported\n");
				printf("supported types: sha1\n");
				exit(1);
			}
		}
	}
	createCompinations(chars, partial, desiredLen, fileLocation);
	return returnCode;
}

void createCompinations(char chars[150], char inputText[100], int desiredLen, char fileLocation[150]) {
	char compiledText[150] = "";
	int i = 0;
	for(i = 0; i < strlen(chars); i++) {
		strncpy(compiledText, inputText, desiredLen);
		append(compiledText, chars[i]);
		if ( strlen(compiledText) == desiredLen){
			//printf("hashNum: %d\n", hashNum);
			if(hashNum != 0){
				switch (hashNum) {
					case 1: createMD5Hash(compiledText, fileLocation);
					break;
					case 2: createSHA1Hash(compiledText, fileLocation);
					break;
					case 3: createSHA224Hash(compiledText, fileLocation);
					break;
					case 4: createSHA256Hash(compiledText, fileLocation);
					break;
					case 5: createSHA384Hash(compiledText, fileLocation);
					break;
					case 6: createSHA512Hash(compiledText, fileLocation);
					break;
				}
			}
			else if (quiet != 1) {
				printf(compiledText);
				printf("\n");
			}
		}
		if ( strlen(compiledText) != desiredLen) {
			createCompinations(chars, compiledText, desiredLen, fileLocation);
		}
	}
}

void createSHA1Hash(char hashInput[50], char fileLocation[150]) {
	int i;
	unsigned char d[20];
	SHA_CTX sha1;
	SHA1_Init(&sha1);
	SHA1_Update(&sha1, (const unsigned char *) hashInput, strlen(hashInput));
	if (!SHA1_Final(d, &sha1))
	{
		fprintf(stderr, "ERROR-- could not compute message digest\n");
	}
	else
    {
    	if (quiet != 1) {printf("text: %s, hash: ", hashInput);}
    	if (printToFile == 1) {
    		fp = fopen(fileLocation, "a");
    		fprintf(fp, "%s ", hashInput);
    	}
        for(i = 0; i < 20 ; i++)
        {
        	if (quiet != 1) {
        		printf("%02x", d[i]);
        	}
        	if (printToFile == 1) {
				fp = fopen(fileLocation, "a");
            	fprintf(fp, "%02x", d[i]);
            }
        }
        if (quiet != 1) {
        	printf("\n");
        }
    	if (printToFile == 1) {fprintf(fp, "\n");fclose(fp);}
        //SHA1R(&sha1);
    }
    
}

void createSHA224Hash(char hashInput[50], char fileLocation[50]) {
	int i;
	EVP_MD_CTX mdctx;
    unsigned char d[28];
    unsigned int md_len;

    EVP_DigestInit( &mdctx, EVP_sha224() );
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

void createSHA256Hash(char hashInput[50], char fileLocation[50]) {
	int i;
	EVP_MD_CTX mdctx;
    unsigned char d[28];
    unsigned int md_len;

    EVP_DigestInit( &mdctx, EVP_sha256() );
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

void createSHA384Hash(char hashInput[50], char fileLocation[50]) {
	int i;
	EVP_MD_CTX mdctx;
    unsigned char d[28];
    unsigned int md_len;

    EVP_DigestInit( &mdctx, EVP_sha384() );
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

void createSHA512Hash(char hashInput[50], char fileLocation[50]) {
	int i;
	EVP_MD_CTX mdctx;
    unsigned char d[64];
    unsigned int md_len;

    EVP_DigestInit( &mdctx, EVP_sha512() );
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

void createMD5Hash(char hashInput[50], char fileLocation[150]) {
	//printf("inide hash func\n");
	int i;
	unsigned char d[16];
	unsigned char str_enc[32];
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update (&ctx, (const unsigned char *) hashInput, strlen(hashInput));
    MD5_Final(d, &ctx);

    if (quiet != 1) {printf("text: %s, hash: ", hashInput);}
    if (printToFile == 1) {
    	fp = fopen(fileLocation, "a");
    	fprintf(fp, "%s ", hashInput);
    }
    for (i = 0; i < 16; i++) {
    	if (quiet != 1) {
        	printf("%02x", d[i]);
    	}
    	if (printToFile == 1) {
    		fprintf(fp, "%02x", d[i]);
    	}
    }
    if (quiet != 1) {printf("\n");}
    if (printToFile == 1) {fprintf(fp, "\n");fclose(fp);}
    str_enc[32] = 0;
}
