#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<sys/types.h> 
/*for getting file size using stat()*/
#include<sys/stat.h>
 
//SSL
#include <openssl/ssl.h>

#include <errno.h>

char password[7];
void load_certificate(SSL_CTX  *);
int pem(char *, int , int , void *);


void list(char *);
int get(char *,char *);
void put(char *,char *);

 
int main()
{
    FILE *filehd;
    struct sockaddr_in server, client;
    struct stat obj;
    int sock1, sock2;
    char command[20];
    int k, i, size, len, c,ret,p;
    char filel[300],gfiln[20];
    char ch,pfiln[20],inp[1000];
    int err[5];
    char usern[20],passwd[20],susern[20],spasswd[20],shut[10],*f;
    int j=0,auth[5],fsize;
	    i=0;
	strcpy(susern,"ankith");
	strcpy(spasswd,"123456");
	
	SSL_CTX *ctx;										//SSL pointers
	SSL *ssl;	

	
	  sock1 = socket(AF_INET, SOCK_STREAM, 0);			//socket
	  if(sock1 == -1)
    		{
		      printf("Socket creation failed\n");
		      exit(1);
		    }
	  server.sin_family=AF_INET;
	  server.sin_port = htons(3000);
	  inet_aton("127.0.0.1",&(server.sin_addr));
 
	 k = bind(sock1,(const struct sockaddr*)&server,sizeof(server)); 	//bind
	  if(k == -1)
		    {
			      printf("Binding error\n");
			      exit(1);
		    }
	  k = listen(sock1,1);							//listen
	  if(k == -1)
    		{
			      printf("Listen failed\n");
			      exit(1);
		    }
		printf("listening\n");	

	    strcpy(password,"spfile");						//SSL
	    SSL_library_init();										
	    SSL_load_error_strings();
		const SSL_METHOD *meth=SSLv23_server_method();				//method
		if(meth==NULL)
			{	//perror(error);	
				printf("ctx method creation failed\n");
				return -1;
			}

		
	ctx=SSL_CTX_new(meth);										//CTX Method
	if(ctx==NULL)
			{	//perror(error);	
				printf("ctx method creation failed\n");
				return -1;
			}

	  load_certificate(ctx);					//load_certificate call
	  len = sizeof(client);
	  sock2 = accept(sock1,(struct sockaddr*)&client, &len);
	  i = 1;
	  if(sock2<0)
		{
			//perror(error);	
			printf("unable to create accept fd\n");
			return -1;
		}
			ssl=SSL_new(ctx);			//SSL OBJECTS
			if(ssl==NULL)
			{
				printf("unable to create ssl object \n");
				return -1;
			}

		SSL_set_fd(ssl,sock2);
		ret=SSL_accept(ssl);
			if(ret<0)
 
			{	//perror(error);	
				p=SSL_get_error(ssl,ret);
				printf("p value: %d \n",p);
				return -1;
			}

			/*SSL_read(ssl,mss,sizeof(mss));
			printf("data read : %s\n",mss);*/

			SSL_read(ssl,usern,sizeof(usern));
			SSL_read(ssl,passwd,sizeof(passwd));
			
			if(!strcmp(susern,usern)&&!strcmp(spasswd,passwd))
				{
					auth[0]=0;
				}
			else
				{
					auth[0]=1;
					 SSL_shutdown(ssl);
					 close(sock2);
					exit(1);
				}
	
			SSL_write(ssl,auth,sizeof(auth));
			
  while(1)
	    {	  

		
            SSL_read(ssl, command, 100);				//recv to read
            // sscanf(buf, "%s", command);
            if(!strcmp(command, "ls"))
            {
                list(filel);
                SSL_write(ssl,filel,sizeof(filel));
                memset(command,'\0',sizeof(command));
					  
            }
            else if(!strcmp(command,"get"))
            {
                SSL_read(ssl,gfiln,sizeof(gfiln));
                //err[0]=get(gfiln,f,fsize);
                stat(gfiln,&obj);
                filehd=fopen(gfiln,"r");
                fsize = obj.st_size;
                printf("file size=%d\n",fsize);
                if(filehd!=NULL)
                {
                    f=malloc(fsize);
                    err[0]=get(gfiln,f);
                    SSL_write(ssl,err,sizeof(err));
                    SSL_write(ssl,&fsize,sizeof(int));
                    SSL_write(ssl,f,fsize);
                    fclose(filehd);
                    }
                else
                {
                    err[0]=1;
                    SSL_write(ssl,err,sizeof(err));
                    fclose(filehd);
                }
            }
						 
				
            else if(!strcmp(command, "put"))
            {
                SSL_read(ssl,pfiln,sizeof(pfiln));
                SSL_read(ssl,&fsize,sizeof(int));
                f=malloc(fsize);
                SSL_read(ssl,f,fsize);
                put(pfiln,f);
                memset(f,'\0',fsize);
                memset(command,'\0',sizeof(command));
                }
            else if(!strcmp(command, "quit"))
            {
                SSL_read(ssl,shut,sizeof(shut));
                if(shut[0]==-1)
                    {
                    SSL_shutdown(ssl);//close the waiting ports
                    close(sock2);
                    exit(0);
                    }
				}	

			    }
        SSL_shutdown(ssl);
        close(sock2);
        return 0;
        }

void load_certificate(SSL_CTX *ctx)
	{
		int ret;

		ret=SSL_CTX_use_certificate_file(ctx,"servercert/server.crt",SSL_FILETYPE_PEM);		//load server certificate
		if(ret<0)
			{
				printf("error getting certificate\n");
				return;
			}		
		SSL_CTX_set_default_passwd_cb(ctx,pem);				//set password
		
		ret=SSL_CTX_use_PrivateKey_file(ctx,"servercert/server.key",SSL_FILETYPE_PEM);			//SERVER private key
		if(ret<0)
			{
				printf("error getting server private key\n");
				return;
			}		
			
		ret=SSL_CTX_load_verify_locations(ctx,"servercert/ca.crt",NULL);			//load CA cert
		if(ret<0)
			{
				printf("error getting CA certificate\n");
				return;
			}	
		SSL_CTX_set_verify_depth(ctx,1);	

	}

int pem(char *buf, int size, int rwflag, void *userdata)
		{
			 strncpy(buf, (char *)(password), size);
			 buf[size - 1] = '\0';
			 return(strlen(buf));
		}


void list(char *inp)
{
    FILE *filehd;
    char ch;
    int i=0;
    system("ls >temp.txt");
    filehd=fopen("temp.txt","r");
    ch=fgetc(filehd);
    while(ch!=EOF)
    {
        inp[i++]=ch;
        ch=fgetc(filehd);
    }
    inp[i]='\0';
    fclose(filehd);
}

int get(char *fn,char *fip)
{
    FILE *gfilehd;
    int j=0;
    char ch;
    
    gfilehd=fopen(fn,"r");
    
    if(gfilehd!=NULL)
    {
        ch=fgetc(gfilehd);
        while(ch!=EOF)
            {
                fip[j++]=ch;
                ch=fgetc(gfilehd);
            }
        fip[j]='\0';
        fclose(gfilehd);
            return 0;
    }
    else
        return 1;
}
void put(char *pn,char *foup)
{
    FILE *pfilehd;
    
    pfilehd=fopen(pn,"w");
    
    fputs(foup,pfilehd);
    fclose(pfilehd);

}








































