//tunnel used to connect host which run tunnld.
#ifndef __TUNNEL_H__
#define __TUNNEL_H__

#include <time.h>


#define TUNNEL_DEBUG 0
//#define BUILD_LIBRARY_TUNNEL

#if TUNNEL_DEBUG

#define DBUG_SOCK_INFO(fd) \
do{ \
    struct sockaddr_in in_addr = {0}; \
    socklen_t nl = sizeof(in_addr); \
    if(getsockname(fd, (struct sockaddr *) &in_addr, &nl) !=-1) \
    { \
        LOG_INFO("fd(%d),ip(%s),port(%d)",fd,inet_ntoa(in_addr.sin_addr),ntohs(in_addr.sin_port)); \
    } \
}while(0)

#define DBUG_PEER_SOCK_INFO(fd) \
do{ \
    struct sockaddr_in in_addr = {0}; \
    socklen_t nl = sizeof(in_addr); \
    getpeername(fd, (struct sockaddr *) &in_addr, &nl); \
    LOG_INFO("fd(%d),ip(%s),port(%d)",fd,inet_ntoa(in_addr.sin_addr),ntohs(in_addr.sin_port)); \
}while(0)

#define LOG_INFO(fmt,...) \
do{	\
	struct tm *p; \
	time_t timep; \
	time(&timep); \
	p = gmtime(&timep); \
	printf("%d-%d-%d %d:%02d:%02d %s$%d:"fmt"\r\n",1900+p->tm_year,1+p->tm_mon,p->tm_mday \
			,8+p->tm_hour,p->tm_min,p->tm_sec \
			,__func__,__LINE__,##__VA_ARGS__); \
}while(0)

#define LOG_DEBUG LOG_INFO

#define PRINT_RECV_DATA(data,dlen,limit_len) \
do{ \
    char *tmp = NULL; \
    int length; \
    if(limit_len) \
        length = (dlen>200)?200:dlen;   \
    else \
        length = dlen; \
    if(data!=NULL && length>0) \
    { \
        tmp = malloc(length+2); \
        if(tmp) \
        { \
            snprintf(tmp,length+1,"%s",data); \
            LOG_DEBUG("\n%s",tmp); \
            free(tmp); \
        } \
    } \
}while(0)

#else
#define DBUG_SOCK_INFO(fd)
#define DBUG_PEER_SOCK_INFO(fd)
#define LOG_INFO(fmt,...) \
do{	\
	struct tm *p; \
	time_t timep; \
	time(&timep); \
	p = gmtime(&timep); \
	printf("%d-%d-%d %d:%02d:%02d %s$%d:"fmt"\r\n",1900+p->tm_year,1+p->tm_mon,p->tm_mday \
			,8+p->tm_hour,p->tm_min,p->tm_sec \
			,__func__,__LINE__,##__VA_ARGS__); \
}while(0)
#define LOG_DEBUG
#define PRINT_RECV_DATA(data,dlen)
#endif

#define SOCKET_NO_BLOCK 0
#define SOCKET_BLOCK 1
#define RECV_BUFF_SIZE 1024
typedef enum
{
    TUNNEL_FD_TYPE_NOT_SET = 0,
    TUNNEL_FD_MGNT_TLD = 1,	/* communicate with tunneld fd,mangement socket fd */
    TUNNEL_FD_LSRV,	/* receive or send to local service fd */
    TUNNEL_FD_LSRV2TLD,	/* local service data to tunnled fd */
    TUNNEL_FD_TYPE_COUNT
} TUNNEL_FD_TYPE;

typedef enum
{
    TUNNEL_MGNT_TYPE_NOT_SET = 0,
#define TUNNEL_MGNT_TYPE_NOT_SET TUNNEL_MGNT_TYPE_NOT_SET
    TUNNEL_MGNT_TYPE_CHECK_PWD = 1,
#define TUNNEL_MGNT_TYPE_CHECK_PWD TUNNEL_MGNT_TYPE_CHECK_PWD
    TUNNEL_MGNT_TYPE_REQUEST = 2,
#define TUNNEL_MGNT_TYPE_REQUEST TUNNEL_MGNT_TYPE_REQUEST
} TUNNEL_MGNT_TYPE;

typedef enum
{
    TUNNEL_MGNT_STATUS_NOT_SET = 0x0,
#define TUNNEL_MGNT_STATUS_NOT_SET TUNNEL_MGNT_STATUS_NOT_SET
    TUNNEL_MGNT_STATUS_PWD_CHECKED = 0x1,
#define TUNNEL_MGNT_STATUS_PWD_CHECKED TUNNEL_MGNT_STATUS_PWD_CHECKED
    TUNNEL_MGNT_STATUS_LSRV_CONN  = 0x2, //local service socket connnected
#define TUNNEL_MGNT_STATUS_LSRV_CONN TUNNEL_MGNT_STATUS_LSRV_CONN
    TUNNEL_MGNT_STATUS_LSRV2TLD_CONN = 0x4, //local service data to tunneld connected
#define TUNNEL_MGNT_STATUS_LSRV2TLD_CONN TUNNEL_MGNT_STATUS_LSRV2TLD_CONN
} TUNNEL_MGNT_STATUS;

typedef struct
{
    int fd;
    TUNNEL_FD_TYPE type;
    char *rdata;    //read data
    int rdlen;      //read data length
    char *wdata;    //write data
    int wdlen;      //write data length
} TUNNEL_FD,*pTUNNEL_FD;

typedef struct _TUNNELD_REQRESP_PAIR
{
    TUNNEL_FD lsrv;         /* receive or send to local service fd */
    TUNNEL_FD lsrv2Tld;     /* local service data to tunnled fd */
} TUNNEL_REQRESP_PAIR_TYPE,*pTUNNEL_REQRESP_PAIR_TYPE;

typedef struct _TUNNEL_FD_LINK_LIST     //tunnel fd link list
{
    pTUNNEL_FD ptfd;
    struct _TUNNEL_FD_LINK_LIST *next;
} TUNNEL_FD_LINK_LIST,*pTUNNEL_FD_LINK_LIST;

#ifdef BUILD_LIBRARY_TUNNEL
typedef void* (*CONN_TUNNEL_CALLBACK)(int reqPort);
typedef void (*CLOSE_TUNNEL_CALLBACK)();
int create_tunnel_ex(char *ip, int r_port, int l_port, char *password);
void set_connTunnel_cb(CONN_TUNNEL_CALLBACK conn_fun);
void set_closeTunnel_cb(CLOSE_TUNNEL_CALLBACK cb);
void close_tunnel_ex();

#endif

#endif
