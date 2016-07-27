#include<stdio.h>
#include <sys/types.h>         
#include <sys/socket.h>
#include<string.h>
#include <unistd.h>
#include<netinet/in.h>
#include<arpa/inet.h>	
#include<stdlib.h>
#include <openssl/ssl.h>
/*for getting file size using stat()*/
#include<sys/stat.h>



char password[8];
void load_certificate(SSL_CTX  *);
int pem(char *, int , int , void *);
void getf(char *,char *);
void putf(char *,char *);

int main(int argc,char *argv[])
{
    FILE *filehd;
    struct sockaddr_in server;
    int sock;
    int choice;
    char command[20];
    int k, size, status,ret,j=0;
    char usern[20],passwd[20],ip[15],shut[10],ch;
    struct stat obj;
    char filel[300],gfiln[20],pfnam[20],pfilc[1000],*f;
    int err[5],p,auth[5],csize;

    strcpy(ip,argv[1]);
    printf("ip:%s\n",ip);
    printf("enter username:\n");
    scanf("%s",usern);
    printf("enter password\n");
    scanf("%s",passwd);
    SSL_CTX *ctx;								//SSL pointers
    SSL *ssl;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock == -1)
        {
            printf("socket creation failed\n");
            exit(1);
        }
		strcpy(password,"clpfile");
        SSL_library_init();								//SSL
		SSL_load_error_strings();

		const SSL_METHOD *meth=SSLv23_client_method();	//method
		
		ctx=SSL_CTX_new(meth);								//CTX Method
		if(ctx==NULL)
			{
				printf("ctx method creation failed\n");
				return -1;
			}
		
		load_certificate(ctx);					//load_certificate call
        server.sin_family=AF_INET;
        server.sin_port = htons(3000);
        inet_aton(ip,&(server.sin_addr));
        k = connect(sock,(struct sockaddr*)&server, sizeof(server));
        if(k == -1)
        {
            printf("Connect Error\n");
            exit(1);
        }
		  //int i = 1;
        ssl=SSL_new(ctx);							//SSL OBJECTS
        if(ctx==NULL)
        {
        printf("unable to create ssl object \n");
        return -1;
        }

		SSL_set_fd(ssl,sock);
		ret=SSL_connect(ssl);
			if(ret<0)
			{
				printf("error mapping ssl object\n");
				return -1;
			}
			
			/*strcpy(mss,"hello world");
			SSL_write(ssl,mss,sizeof(mss));*/
			
			SSL_write(ssl,usern,sizeof(usern));
			SSL_write(ssl,passwd,sizeof(passwd));
			SSL_read(ssl,auth,sizeof(auth));
			if(auth[0]!=0)
				{
					printf("invalid credentials!!\n");
					printf("server shutting down\n");
					SSL_shutdown(ssl);
					close(sock);
					exit(1);	
				}
while(1)
			    
    {
    printf("Enter a choice:\n1. get 2. put 3.ls 4. help 5. quit\n");
    scanf("%d", &choice);
    switch(choice)
    {
        case 1:
                strcpy(command,"get");
                SSL_write(ssl,command,sizeof(command));
                printf("enter file name\n");
                scanf("%s",gfiln);
                SSL_write(ssl,gfiln,sizeof(gfiln));
                //printf("file name sent\n");
                SSL_read(ssl,err,sizeof(err));
                if(err[0]==1)
                {
                    printf("file not found!!\n");
                    SSL_shutdown(ssl);
                    close(sock); //file not found
                    }
                else
                {
                    SSL_read(ssl,&csize,sizeof(int));
                    printf("file size=%d\n",csize);
                    f=malloc(csize);
                    SSL_read(ssl,f,csize);
                    getf(gfiln,f);
                    printf("file %s copied from server successfully !\n",gfiln);
                    //memset(f,'\0',csize);
                }
                break;
        case 2:
                strcpy(command,"put");
                SSL_write(ssl,command,sizeof(command));
                printf("enter file to be put:\n");
                scanf("%s",pfnam);
                filehd=fopen(pfnam,"r");
                stat(pfnam,&obj);
                csize = obj.st_size;
                printf("file size=%d\n",csize);
                if(filehd!=NULL)
                {
                    SSL_write(ssl,pfnam,sizeof(pfnam));
                    SSL_write(ssl,&csize,sizeof(int));
                    f=malloc(csize);
                    putf(pfnam,f);
                    SSL_write(ssl,f,csize);
                    printf("%s\n",f);
                    printf("file sent successfully !!\n");
                }
                else
                {
                    printf("file doesn't exsist !!\n");
                    SSL_shutdown(ssl);
                    close(sock);// close as file doesn't exsist
                }
                break;
        case 3:
                strcpy(command,"ls");
                SSL_write(ssl,command,sizeof(command));
                SSL_read(ssl,filel,sizeof(filel));
                printf("list of files :\n%s \n",filel);
                break;
        case 4:
                printf("command help! :\n");
                printf("> get : get command can be used to get files from the server onto the client's systsem.\n");
                printf("> put : put command can be used to put a file from client's system onto the server.\n");
                printf("> ls : ls command lists the files in the current directory of the server.\n");
                printf("> quit : terminates the connection \n");
						break;
										
        case 5:
                strcpy(command,"quit");
                SSL_write(ssl,command,sizeof(command));
                shut[0]=-1;
                SSL_write(ssl,shut,sizeof(shut));
                printf("Server closed\nQuitting..\n");
                SSL_shutdown(ssl);
                close(sock);
                exit(0);
                }
											
            }
        SSL_shutdown(ssl);
        close(sock);
        return 0;
}

void load_certificate(SSL_CTX *ctx)
	{
		int ret;

		ret=SSL_CTX_use_certificate_file(ctx,"cert/client.crt",SSL_FILETYPE_PEM);				//load server certificate
		if(ret<0)
			{
				printf("error getting certificate\n");
			}		
		SSL_CTX_set_default_passwd_cb(ctx,pem);				//set password
		
		ret=SSL_CTX_use_PrivateKey_file(ctx,"cert/client.key",SSL_FILETYPE_PEM);			//SERVER private key
		if(ret<0)
			{
				printf("error getting private key\n");
			}		
			
		ret=SSL_CTX_load_verify_locations(ctx,"cert/ca.crt",NULL);			//load CA cert
		if(ret<0)
			{
				printf("error getting CA certificate\n");
			}
	SSL_CTX_set_verify_depth(ctx,1);	
		

	}

int pem(char *buf, int size, int rwflag, void *userdata)
		{
			 strncpy(buf, (char *)(password), size);
			 buf[size - 1] = '\0';
			 return(strlen(buf));
		}

void getf(char *gfn,char *gfc)
{
    FILE *gfilehd;
    
    gfilehd=fopen(gfn,"w");
    
    fputs(gfc,gfilehd);
    fclose(gfilehd);
}

void putf(char *pfn,char *pfc)
{
    FILE *pfilhd;
    char ch;
    int j=0;
    pfilhd=fopen(pfn,"r");
    ch=getc(pfilhd);
    while(ch!=EOF)
    {
        pfc[j++]=ch;
        ch=getc(pfilhd);
    }
    pfc[j]='\0';
        
    
}



















		
