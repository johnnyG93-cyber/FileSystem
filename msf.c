// The MIT License (MIT)
//
// Copyright (c) 2016 Trevor Bakker
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>

#define NUM_BLOCKS 65536
#define BLOCK_SIZE 1024
#define BLOCKS_PER_FILE 1024
#define NUM_FILES 256
#define FIRST_DATA_BLOCK 1001
#define MAX_FILE_SIZE 1048576

uint8_t data[NUM_BLOCKS][BLOCK_SIZE];
unsigned char file_data[NUM_BLOCKS][BLOCK_SIZE];


// 512 blocks just for free block map
uint8_t * free_blocks;
uint8_t * free_inodes;

struct directoryEntry
{
    char filename[64];
    short in_use;
    int32_t inode;

};

struct directoryEntry * directory;

struct pre_delete
{
	char filename[64];
	int directoryEntry;

};
struct pre_delete  deleted;

struct inode
{
    int32_t blocks[BLOCKS_PER_FILE];
    short in_use;
	uint8_t attribute;
	uint32_t file_size;
};

struct inode * inodes;

FILE *fp;
char image_name[64];
uint8_t image_open;

#define WHITESPACE " \t\n"      // We want to split our command line up into tokens
								// so we need to define what delimits our tokens.
								// In this case  white space
								// will separate the tokens on our command line

#define MAX_COMMAND_SIZE 255    // The maximum command-line size

#define MAX_NUM_ARGUMENTS 5     // Mav shell only supports four arguments

int32_t findFreeBlock()
{
	int i;
	for(i = 0; i < NUM_BLOCKS; i++)
	{
		if(free_blocks[i])
		{
			return i + 1001;
		}
	}
	return -1;
}

int32_t findFreeInode()
{
	int i;
	for(i = 0; i < NUM_FILES; i++)
	{
		if(free_inodes[i])
		{
			return i;
		}
	}
	return -1;
}
int32_t findFreeInodeBlock(int32_t inode)
{
	int i;
	for(i = 0; i < BLOCKS_PER_FILE; i++)
	{
		if(inodes[inode].blocks[i]== -1)
		{
			return i;
		}
	}
	return -1;
}
void init( )
{
    directory = (struct directoryEntry *)&data[0][0];
    inodes = (struct inode *)&data[20][0];
	free_blocks = (uint8_t *)&data[1000][0];
	free_inodes = (uint8_t *)&data[19][0];

	memset(image_name, 0, 64);
	image_open = 0;

    for(int i=0; i<NUM_FILES; i++)
    {
      directory[i].in_use = 0;
      directory[i].inode = -1;
	  free_inodes[i] = 1;
      memset(directory[i].filename, 0, 64);

      for(int j=0; j< NUM_BLOCKS; j++)
      {
        inodes[i].blocks[j] = -1;
        inodes[i].in_use = 0;
		inodes[i].attribute = 0;
		inodes[i].file_size = 0;
      }

    }
	for(int j=0; j< NUM_BLOCKS; j++)
    {
    	free_blocks[j] = 1;
	}
}
void encrypt(char *filename, uint8_t cipher)
{
    int32_t inode_num = findFreeInode();

    if (inode_num == -1)
    {
        printf("ERROR: File '%s' not found.\n", filename);
        return;
    }

    // check if the file is already encrypted
    if (inodes[inode_num].attribute & 0x01)
    {
        printf("ERROR: File '%s' is already encrypted.\n", filename);
        return;
    }

    // set the encrypted attribute bit of the file
    inodes[inode_num].attribute |= 0x01;

    // loop through each block of the file and XOR with the cipher
    for (int i = 0; i < BLOCKS_PER_FILE; i++)
    {
        int32_t block_num = inodes[inode_num].blocks[i];
        if (block_num == -1)
            break;
        for (int j = 0; j < BLOCK_SIZE; j++)
        {
            data[block_num][j] ^= cipher;
        }
    }

    printf("File '%s' has been encrypted with cipher '%d'.\n", filename, cipher);
}
void decrypt(char *filename, uint8_t cipher)
{
    int32_t index = findFreeInode();
    if(index == -1)
    {
        printf("ERROR: File not found\n");
        return;
    }

    struct inode file_inode = inodes[index];
    if(!file_inode.in_use)
    {
        printf("ERROR: File not found\n");
        return;
    }

    // check if file is encrypted
    if ((file_inode.attribute & 0x1) == 0)
    {
        printf("ERROR: File is not encrypted\n");
        return;
    }

    // decrypt file content
    uint8_t *buffer = malloc(file_inode.file_size);
    if (buffer == NULL)
    {
        printf("ERROR: Unable to allocate memory\n");
        return;
    }
    int32_t num_blocks = (file_inode.file_size + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for(int i = 0; i < num_blocks; i++)
    {
        int32_t block_index = file_inode.blocks[i];
        if(block_index == -1)
        {
            break;
        }
        uint8_t *block_data = data[block_index];
        int32_t num_bytes = i == num_blocks-1 ? file_inode.file_size % BLOCK_SIZE : BLOCK_SIZE;
        for(int j = 0; j < num_bytes; j++)
        {
            buffer[i*BLOCK_SIZE + j] = block_data[j] ^ cipher;
        }
    }

    // write decrypted content back to file
    FILE *fp = fopen(image_name, "rb+");
    if(fp == NULL)
    {
        printf("ERROR: Unable to open file\n");
        return;
    }
    fseek(fp, (FIRST_DATA_BLOCK + file_inode.blocks[0]) * BLOCK_SIZE, SEEK_SET);
    fwrite(buffer, file_inode.file_size, 1, fp);
    fclose(fp);
    free(buffer);

    // update file attributes
    inodes[index].attribute &= ~0x1; // clear the encryption flag
    printf("File decrypted successfully.\n");
}
void read_file(char* filename, int starting_byte, int num_bytes) 
{
    int32_t index = -1;
    int32_t num_blocks_needed = 0;
    int32_t num_blocks_to_read = 0;

    // Find the inode for the file
    for(int i = 0; i < NUM_FILES; i++) {
        if(directory[i].in_use == 1 && strcmp(directory[i].filename, filename) == 0) {
            index = directory[i].inode;
            break;
        }
    }

    if(index == -1) {
        printf("ERROR: File not found\n");
        return;
    }

    // Calculate the number of blocks needed to read num_bytes
    if(num_bytes % BLOCK_SIZE == 0) {
        num_blocks_needed = num_bytes / BLOCK_SIZE;
    } else {
        num_blocks_needed = (num_bytes / BLOCK_SIZE) + 1;
    }

    // Calculate the number of blocks to read
    if((inodes[index].file_size - starting_byte) % BLOCK_SIZE == 0) {
        num_blocks_to_read = (inodes[index].file_size - starting_byte) / BLOCK_SIZE;
    } else {
        num_blocks_to_read = ((inodes[index].file_size - starting_byte) / BLOCK_SIZE) + 1;
    }

    // Check if the starting byte is valid
    if(starting_byte >= inodes[index].file_size) {
        printf("ERROR: Starting byte is beyond the end of file\n");
        return;
    }

    // Check if the number of bytes requested is valid
    if(starting_byte + num_bytes > inodes[index].file_size) {
        printf("ERROR: Number of bytes requested exceeds file size\n");
        return;
    }

    // Check if there are enough blocks to read
    if(num_blocks_needed > num_blocks_to_read) {
        printf("ERROR: Not enough blocks in file to read\n");
        return;
    }

    // Read the blocks and print the data in hexadecimal format
    int32_t current_block = starting_byte / BLOCK_SIZE;
    int32_t current_byte = starting_byte % BLOCK_SIZE;
    int32_t bytes_read = 0;

    while(bytes_read < num_bytes) {
        int32_t block_index = inodes[index].blocks[current_block];
        int32_t bytes_to_read = BLOCK_SIZE - current_byte;
        if(bytes_to_read > num_bytes - bytes_read) {
            bytes_to_read = num_bytes - bytes_read;
        }
        for(int i = 0; i < bytes_to_read; i++) {
            printf("%02X ", data[block_index][current_byte + i]);
        }
        current_block++;
        current_byte = 0;
        bytes_read += bytes_to_read;
    }

    printf("\n");
}
void delete(char* filename)
{
	for(int i = 0; i < NUM_FILES; i++)
	{
		if(strcmp(directory[i].filename, filename) == 0 && directory[i].in_use == 1)
		{
			deleted.directoryEntry = i;
			strcpy(deleted.filename, filename); 
			//printf("%s",deleted.filename);
			//found the file, mark it as deleted and free up its blocks
			directory[i].in_use = 0;

			int index = directory[i].inode;

			for(int j = 0; j < BLOCKS_PER_FILE; j++)
			{
				if(inodes[index].blocks[j] != -1)
				{
					free_blocks[j] = 1;
					inodes[index].blocks[j] = -1;
				}
			}
		}
	}
}
void undelete(char* filename)
{
	
		if(strcmp(deleted.filename, filename) == 0 && directory[deleted.directoryEntry].in_use == 0)
		{
			//found the file, mark it as deleted and free up its blocks
			directory[deleted.directoryEntry].in_use = 1;

			int index = directory[deleted.directoryEntry].inode;

			for(int j = 0; j < BLOCKS_PER_FILE; j++)
			{
				if(inodes[index].blocks[j] == -1)
				{
					if(inodes[index].blocks[j] == -1)
					{
						inodes[index].blocks[j] = findFreeBlock( );
						if(inodes[index].blocks[j] == -1)
						{
							printf("ERROR: File system full\n");
							exit(1);
						}
					}
				}
			}
		}
	
	printf("undelete: Can not find the file.\n");
}
uint32_t df( )
{
		int count = 0;
		for(int j=FIRST_DATA_BLOCK; j< NUM_BLOCKS; j++)
		{
			if(free_blocks[j])
			{
				count++;
			}
				
		}
		return count * BLOCK_SIZE;	
}
	
void createfs(char * filename)
{
  fp = fopen(filename, "w");

  if(fp == NULL)
  {
	printf("File did not open");
  }
  strncpy(image_name, filename, strlen(filename));

  memset(data, 0, NUM_BLOCKS * BLOCK_SIZE);

  image_open = 1;

  for(int i=0; i<NUM_FILES; i++)
    {
      directory[i].in_use = 0;
      directory[i].inode = -1;
	  free_inodes[i] = 1;

      memset(directory[i].filename, 0, 64);

		for(int j=0; j< NUM_BLOCKS; j++)
		{
			inodes[i].blocks[j] = -1;
			inodes[i].in_use = 0;
			inodes[i].attribute = 0;
			inodes[i].file_size = 0;
		}
	}
	for(int j=0; j< NUM_BLOCKS; j++)
    {
    	free_blocks[j] = 1;
	}

  fclose(fp);
}
void savefs( )
{
	if(image_open == 0)
	{
		printf("ERROR: Disk image is not open.\n");
	}
	fp = fopen(image_name, "w");

	fwrite(&data[0][0], BLOCK_SIZE, NUM_BLOCKS, fp);

	memset(image_name, 0, 64);
	//fclose(fp);
}

char history[15][MAX_COMMAND_SIZE] = {};
int history_idx = 0;
int max_val = 15;
int pids[15] = {};

void openfs(char * filename)
{
	fp = fopen(filename, "r");

	strncpy(image_name, filename, strlen(filename));

	fread(&data[0][0], BLOCK_SIZE, NUM_BLOCKS, fp);
	
	image_open = 1;

	//fclose(fp);
}

void closefs( )
{
	if(image_open == 0)
	{
		printf("ERROR: disk image is not open\n");
		return;
	}
	fclose(fp);
	image_open = 0;
	memset(image_name, 0, 64);

}

void insert(char* filename)
{
	if(filename == NULL)
	{
		printf("Error: filename is NULL.\n");
		return;
	}

	struct stat buf;
	int ret = stat(filename, &buf);

	if(ret == -1)
	{
		printf("Error: file does not exist.\n");
		return;
	}

	if(buf.st_size > MAX_FILE_SIZE)
	{
		printf("Error: file is too large.\n");
		return;
	}

	if(buf.st_size > df())
	{
		printf("Error: not enough free disk space.\n");
		return;
	}

	int i;
	int directory_entry = -1;
	for(i = 0; i < NUM_FILES; i++)
	{
		if(directory[i].in_use == 0)
		{
			directory_entry = i;
			break;
		}
	}

	if(directory_entry == -1)
	{
		printf("Error: could not find a free directory entry.\n");
		return;
	}
	
	FILE *ifp = fopen(filename,"r");
	printf("Reading %d bytes from %s\n", (int) buf.st_size, filename);
	int32_t copy_size = buf.st_size;
	int32_t offset = 0;
	//int block_index = 0;
	int32_t block_index = -1;

	//Find a free node
	int32_t index = findFreeInode();
		if(index == -1)
		{
			printf("Error: cannot find a free inode.\n");
			return;
		}

	//Place file info in the directory
	directory[directory_entry].in_use = 1;
	directory[directory_entry].inode = index;
	strncpy(directory[directory_entry].filename, filename, strlen(filename));

	int32_t bytes = fread( data[block_index], BLOCK_SIZE, 1, ifp);
	//inodes[index].file_size = buf.st_size;

	//save the block in the inode
	int32_t inode_block = findFreeInodeBlock( index );
	inodes[index].blocks[inode_block] = block_index;

	while(copy_size > 0)
	{
		fseek(ifp, offset, SEEK_SET);

		block_index = findFreeBlock();
		if(block_index == -1)
		{
			printf("Error: cannot find a free block.\n");
			return;
		}

		

		

		

		if(bytes == 0 && !feof(ifp))
		{
			printf("ERROR: An error occured reading from the input file.\n");
			return;
		}

		clearerr(ifp);
		copy_size -= BLOCK_SIZE;
		offset += BLOCK_SIZE;
		block_index = findFreeBlock();
	}

	fclose(ifp);
}

void retrieve(char* filename, char* newFilename)
{
	int    status;             
  	struct stat buf;
	status =  stat(filename, &buf );
	if(status != -1)
	{   
		FILE *ifp = fopen (filename, "r" ); 
		printf("Reading %d bytes from %s\n", (int) buf . st_size, filename );
		int copy_size   = buf . st_size;
		int offset = 0;     
		int block_index = 0;
		while( copy_size > 0 )
		{
			fseek( ifp, offset, SEEK_SET );
			int bytes  = fread( file_data[block_index], BLOCK_SIZE, 1, ifp );
			if( bytes == 0 && !feof( ifp ) )
			{
				printf("An error occured reading from the input file.\n");
			}
			clearerr( ifp );
			copy_size -= BLOCK_SIZE;
			offset    += BLOCK_SIZE;
			block_index ++;
		}
		fclose( ifp );

		FILE *ofp;
		ofp = fopen(newFilename, "w");
		if( ofp == NULL )
		{
			ofp = fopen(filename, "w"); 
		}

		block_index = 0;
		copy_size   = buf . st_size;
		offset      = 0;

		if( newFilename == NULL)
		{
			printf("Writing %d bytes to %s\n", (int) buf . st_size, filename);
		}
		else
		{
			printf("Writing %d bytes to %s\n", (int) buf . st_size, newFilename );
		}
		
		while( copy_size > 0 )
		{ 

			int num_bytes;
			if( copy_size < BLOCK_SIZE )
			{
				num_bytes = copy_size;
			}
			else 
			{
				num_bytes = BLOCK_SIZE;
			}
			fwrite( file_data[block_index], num_bytes, 1, ofp );
			copy_size -= BLOCK_SIZE;
			offset    += BLOCK_SIZE;
			block_index ++;
			fseek( ofp, offset, SEEK_SET );
		}
		fclose( ofp );
	}

	else
	{
		printf("Unable to open file: %s\n", filename );
		perror("Opening the input file returned: ");
	}
}

void list( )
{
	int not_found = 1;

	for(int i = 0; i< NUM_FILES; i++)
	{
		if(directory[i].in_use && !(inodes[directory[i].inode].attribute & (1 << 0)))
		{
			not_found = 0;
			char filename[65];
			memset(filename, 0, 65);
			strncpy(filename, directory[i].filename, strlen(directory[i].filename));
			printf("%s\n",filename);
		}
	}
	if(not_found)
	{
		printf("ERROR: No files found.\n");
	}
}

void attrib(char* filename, const char* attr)
{
    int32_t index = -1;

	// Find the file in the directory
    for(int i = 0; i < NUM_FILES; i++)
    {
        if(directory[i].in_use && strcmp(directory[i].filename, filename) == 0)
        {
            index = directory[i].inode;
            break;
        }
    }

	// File not found in the directory
    if(index == -1)
    {
        printf("attrib: File not found.\n");
        return;
    }

	 // Check the attribute option and perform the corresponding operation
	if(strcmp(attr, (const char*) "+h") == 0)
    {
        if (inodes[index].attribute & (1 << 0))
        {
            printf("%s is already hidden.\n", filename);
        }
        else
        {
			// Set the hidden attribute
            inodes[index].attribute |= (1 << 0);
            printf("Hidden attribute set for file: %s\n", filename);
        }
    }
    else if(strcmp(attr, (const char*) "+r") == 0)
    {
        if (inodes[index].attribute & (1 << 1))
        {
            printf("%s is already in read only.\n", filename);
        }
        else
        {
			// Set the read-only attribute
            inodes[index].attribute |= (1 << 1);
            printf("Read-only attribute set %s\n", filename);
        }
    }
    else if(strcmp(attr, (const char*) "-h") == 0)
    {
        if (inodes[index].attribute & (1 << 0))
        {
			// Remove the hidden attribute
            inodes[index].attribute &= ~(1 << 0);
            printf("Hidden attribute removed %s\n", filename);
        }
    }
    else if(strcmp(attr, (const char*) "-r") == 0)
    {
        if (inodes[index].attribute & (1 << 1))
        {
			// Remove the read-only attribute
            inodes[index].attribute &= ~(1 << 1);
            printf("Read-only attribute removed %s\n", filename);
        }
    }
    else
    {
        printf("Invalid attribute command.\n");
    }
}



int main(int argc, char* argv[])
{

	char* command_string = (char*)malloc(MAX_COMMAND_SIZE);

  	fp = NULL;

  	init( );

	while (1)
	{
		// Print out the msh prompt
		printf("mfs> ");

		// Read the command from the commandline.  The
		// maximum command that will be read is MAX_COMMAND_SIZE
		// This while command will wait here until the user
		// inputs something since fgets returns NULL when there
		// is no input
		while (!fgets(command_string, MAX_COMMAND_SIZE, stdin));



		if (history_idx < max_val)
		{
			strcpy(history[history_idx], command_string);
		}
		else
		{
			for (int i = 0; i < 13; i++)
			{
				strcpy(history[i], history[i + 1]);
			}
			strcpy(history[14], command_string);
		}
		history_idx++;





		/* Parse input */
		char* token[MAX_NUM_ARGUMENTS];

		for (int i = 0; i < MAX_NUM_ARGUMENTS; i++)
		{
			token[i] = NULL;
		}


		int   token_count = 0;

		// Pointer to point to the token
		// parsed by strsep
		char* argument_ptr = NULL;

		char* working_string = strdup(command_string);

		// we are going to move the working_string pointer so
		// keep track of its original value so we can deallocate
		// the correct amount at the end
		char* head_ptr = working_string;

		// Tokenize the input strings with whitespace used as the delimiter
		while (((argument_ptr = strsep(&working_string, WHITESPACE)) != NULL) &&
			(token_count < MAX_NUM_ARGUMENTS))
		{
			token[token_count] = strndup(argument_ptr, MAX_COMMAND_SIZE);
			if (strlen(token[token_count]) == 0)
			{
				token[token_count] = NULL;
			}
			token_count++;
		}

		// Now print the tokenized input as a debug check
		// \TODO Remove this for loop and replace with your shell functionality
		int count = 0;

		if (token[0] == NULL)
		{
			continue;
		}

		//using strcmp to check for builtin commands
		if (strcmp(token[0], "quit") == 0)
		{
			exit(0);
		}
		else if (strcmp(token[0], "exit") == 0)
		{
			exit(0);
		}
		else if(strcmp("createfs", token[0])==0)
		{
			if(token[1]== NULL)
			{
				printf("ERROR: No filename specefied\n");
				continue;
			}
			createfs(token[1]);
		}
		else if(strcmp("savefs", token[0])==0)
		{
			savefs( );
		}
		else if(strcmp("open", token[0])==0)
		{
			if(token[1] == NULL)
			{
					printf("ERROR: No Filename specified\n");
					continue;
			}
			openfs( token[1] );
		}
		else if(strcmp("close", token[0])==0)
		{
			closefs( );
		}
		else if (strcmp(token[0], "cd") == 0)
		{
			chdir(token[1]);
		}
		else if(strcmp("list", token[0])==0)
		{
			
			if(!image_open)
			{
					printf("ERROR: Disk image is not opened.\n");
					continue;
			}
			list ( );
		}
		else if(strcmp("df", token[0])==0)
		{
			
			if(!image_open)
			{
				printf("ERROR: Disk image is not opened.\n");
				continue;
			}
			df ( );
			printf("%d bytes free\n",df( ));
		}
		else if(strcmp("delete", token[0])==0)
		{
			if(token[1] == NULL)
			{
					printf("ERROR: No Filename specified\n");
					continue;
			}
			delete( token[1] );
		}
		else if(strcmp("undel", token[0])==0)
		{
			if(token[1] == NULL)
			{
					printf("ERROR: No Filename specified\n");
					continue;
			}
			undelete( token[1] );
		}
		else if(strcmp("read", token[0]) == 0) 
		{
			if(token[1] == NULL || token[2] == NULL || token[3] == NULL) 
			{
				printf("ERROR: Missing arguments\n");
				continue;
			}
			read_file(token[1], atoi(token[2]), atoi(token[3]));
		}
		else if(strcmp("encrypt", token[0])==0)
		{
			if(token[1] == NULL || token[2] == NULL)
			{
				printf("ERROR: Filename or Cipher not specified\n");
				continue;
			}
			encrypt(token[1], atoi(token[2]));
		}
		else if (strcmp("decrypt", token[0]) == 0) 
		{
			if (token[1] == NULL || token[2] == NULL) 
			{
				printf("ERROR: Invalid arguments\n");
				continue;
			}
			decrypt(token[1], atoi(token[2]));
		}
		else if (strcmp(token[0], "history") == 0)
		{
			for (int i = 0; i < max_val; i++)
			{
				printf("[%d]  %s\n", count, history[i]);
				if (count < max_val)
				{
					count++;
				}
			}
		}
		else if (strcmp(token[0], "showpids") == 0)
		{
			for (int i = 0; i < max_val; i++)
			{
				printf("[%d]  %d\n", count, pids[i]);
				count++;
			}
		}
		else if (strcmp(token[0], "!") == 0)
		{
			printf("!");
		}
		else if(strcmp("insert", token[0])== 0)
		{
			if(!image_open)
			{
				printf("Error: Disk image is not opened.\n");
				continue;
			}

			if(token[1] == NULL)
			{
				printf("Error: no filname specified.\n");
				continue;
			}

			insert(token[1]);
		}
		else if (strcmp("retrieve", token[0]) == 0) //retrieve command
		{
			if(token[1] == NULL)
			{
				printf("Error: no filename specified.\n");
				continue;
			}

			char* filename = token[1];
			char* newFileName = NULL;

			if(token[2] != NULL)
			{
				newFileName = token[2];
			}

			retrieve(filename, newFileName);
		}
		else if (strcmp("attrib", token[0]) == 0)
        {
            if (token[1] == NULL || token[2] == NULL || token[3] != NULL)
            {
                printf("Error: invalid command.\n");
            }
            else
            {
                char* attribute = token[1];
                char* filename = token[2];
                attrib(filename, attribute);
            }
        }
		else
		{
			pid_t pid1 = fork();
			if (pid1 == 0)
			{
				int test = execvp(token[0], token);

				if ((test == -1))
				{
					printf("%s: Command not found.\n", token[0]);
					exit(0);
				}
			}
			else
			{
				int status;
				wait(&status);



				if (history_idx < max_val)
				{
					pids[history_idx] = pid1;
				}
				else
				{
					pids[14] = pid1;
				}

			}

		}



		// Cleanup allocated memory
		for (int i = 0; i < MAX_NUM_ARGUMENTS; i++)
		{
			if (token[i] != NULL)
			{
				free(token[i]);
			}
		}

		free(head_ptr);

	}

	free(command_string);


	return 0;
	// e2520ca2-76f3-90d6-0242ac120003
}
