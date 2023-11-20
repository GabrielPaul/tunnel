#ifndef __TUNNELD_H__
#define __TUNNELD_H__

#include "common.h"

#define USE_INI_CONF

#if 1
//#define ZLOG_CONFIG_FILE "../etc/tunneld.conf"
#define LOG_INFO dzlog_info
#define LOG_DEBUG dzlog_debug
//#define LOG_DEBUG
#define LOG_NOTICE dzlog_notice
#else
#define LOG_INFO(fmt,...) printf("%s$%d:"fmt"\r\n",__func__,__LINE__,##__VA_ARGS__);
#define LOG_DEBUG LOG_INFO
#define LOG_NOTICE LOG_INFO
#endif
#define MAX_EVENT 20
#define RECV_BUFF_SIZE 1024

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

#define SOCKET_NO_REUSE 0
#define SOCKET_REUSE 1
#define SOCKET_NO_BLOCK 0
#define SOCKET_BLOCK 1

typedef enum
{
    TUNNELD_FD_NOT_SET = 0,			//socket type not set
    TUNNELD_FD_MGNT_LISTENING,		//listening management socket type
    TUNNELD_FD_MGNT_CONN,			//tunneld socket mangement fd  socket type
    TUNNELD_FD_RESP_CONN,			//receive response data  socket type
    TUNNELD_FD_REQ_LISTENING,		//listening request data socket type
    TUNNELD_FD_REQ_CONN				//receiving request data socket type
} TUNNELD_FD_TYPE;

typedef enum
{
    TUNNELD_STATUS_NOT_SET = 0,
#define TUNNELD_STATUS_NOT_SET TUNNELD_STATUS_NOT_SET
#define TUNNELD_STATUS_NO_CONN TUNNELD_STATUS_NOT_SET
    TUNNELD_STATUS_RESP_CONN = 0x1,
#define TUNNELD_STATUS_RESP_CONN TUNNELD_STATUS_RESP_CONN /* response data socket connected */
    TUNNELD_STATUS_REQ_CONN = 0x2
#define TUNNELD_STATUS_REQ_CONN TUNNELD_STATUS_REQ_CONN /* receiving request data socket connected */
} TUNNELD_SET_STATUS;


typedef enum
{
    TUNNELD_LISTENING_MSG_NOT_SET = 0,
    TUNNELD_LISTENING_MSG_CHK_PWD,
    TUNNELD_LISTENING_MSG_PULL
} TUNNELD_LISTENING_MSG_TYPE;

typedef struct _epoll_fd
{
    int fd;
    TUNNELD_FD_TYPE fd_type;
    char *data; //socket fd received data
    int dlen;   //socket fd received data length
} TUNNELD_FD, *pTUNNELD_FD;

typedef struct _TUNNELD_FD_PAIR
{
    TUNNELD_FD tfd_resp;    //response data socket,type TUNNELD_FD_RESP_CONN
    TUNNELD_FD tfd_req;     //request socket,type TUNNELD_FD_REQ_CONN
} TUNNELD_FD_PAIR, *pTUNNELD_FD_PAIR;

typedef struct _TUNNELD_FD_SET
{
    TUNNELD_FD tfd_mgt;		    //tunneld socket mangement fd,type TUNNELD_FD_MGNT_CONN
    TUNNELD_FD tfd_reqListen;	//listening request socket,type TUNNELD_FD_REQ_LISTENING
    TUNNELD_FD_PAIR tfd_pair[MAX_REQ_RESP_CONN_PAIR];  //request and response pair sockets
    unsigned int tfd_pairNum;   //number of exist request and response pair sockets
    char token[TOKEN_LENGTH];
    void *data;
    int dlen;	//data length
} TUNNELD_FD_SET, *pTUNNELD_FD_SET;

typedef struct _TUNNELD_GNL_LINK       //tunneld general link
{
    void *data;   //point to tunneld socket fd set
    struct _TUNNELD_GNL_LINK *next;
} TUNNELD_GNL_LINK, *pTUNNELD_GNL_LINK;
typedef void *(*FREE_LLST_DATA_FUN)(void *data);

typedef struct
{
    int fd;
    char *data; //data to be send
    int dlen;   //data length
} SendData_tfdThrd_Para;

#endif
