#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <errno.h>
#include <fcntl.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <zlog.h>
#include <arpa/inet.h>
#include "tunneld.h"
#include "common.h"

#ifndef USE_INI_CONF
#define TUNNLED_LISTEN_PORT 8877
//tunnel password check
#define TUNNEL_PASSWD "kdgc_aron"
#define ZLOG_CONFIG_FILE "/home/gab/tunnel_aron/tunneld/etc/tunneld.conf"
#else
#include "linux/limits.h"
#include "iniparser.h"

static int TUNNLED_LISTEN_PORT = 0;
static char TUNNEL_PASSWD[16] = {0};
static char ZLOG_CONFIG_FILE[PATH_MAX] = {0};

#define TUNNELD_CONFIG_FILE "./tunneld.conf"
#define DEFAULT_TUNNELD_LISTEN_PORT "8877"
#define DEFAULT_TUNNELD_PASSWD "kdgc_aron"
#define DEFAULT_TUNNELD_ZLOG_CONFIG_FILE "/home/gab/tunnel_aron/tunneld/etc/tunneld.conf"
#endif

const int SOCKET_REUSE_FLAG = SOCKET_REUSE;
static TUNNELD_GNL_LINK g_tfds_llst= {NULL,NULL}; //global tunnld fd set link list
//static TUNNELD_GNL_LINK g_mgnt_tfd_llst = {NULL,NULL}; //global manage listening tunneld fd link list
//static TUNNELD_GNL_LINK g_req_tfd_llst = {NULL,NULL}; //global request listening tunneld fd link list

const char DEBUG_TUNNELD_FD_TYPE_STR[][64]=
{
    "TUNNELD_FD_NOT_SET",
    "TUNNELD_FD_MGNT_LISTENING",
    "TUNNELD_FD_MGNT_CONN",
    "TUNNELD_FD_RESP_CONN",
    "TUNNELD_FD_REQ_LISTENING",
    "TUNNELD_FD_REQ_CONN"
};

static int modify_epoll_tfd(int epfd,int fd,void *epoll_ptr);

static int gen_randStr(char *str,int size)
{
    int i;

    srand(time(NULL));
    for (i = 0; i < size - 2; i++)
    {
        int flag = rand() % 3;
        switch (flag)
        {
            case 0:
                str[i] = rand() % 26 + 'a';
                break;
            case 1:
                str[i] = rand() % 26 + 'A';
                break;
            case 2:
                str[i] = rand() % 10 + '0';
                break;
        }
    }
    str[size - 1] = 0;
    return 0;
}

static TUNNELD_LISTENING_MSG_TYPE get_ListenMsgType(char *data, int dlen)
{
    char cmd[TUNNELD_CMD_LENGTH] = {0};

    assert(data!=NULL);
    sscanf(data,"%s",cmd);
    if(strcmp(cmd,TUNNEL_PASSWD_CMD) == 0)
    {
        return TUNNELD_LISTENING_MSG_CHK_PWD;
    }
    else if(strcmp(cmd,TUNNELD_LISTENING_MSG_PULL_CMD) == 0)
    {
        return TUNNELD_LISTENING_MSG_PULL;
    }
    return TUNNELD_LISTENING_MSG_NOT_SET;
}

//************** socket operation start **************
static int socket_tunneld(int port,int reuse,int block)
{
    int fd = -1;
    struct sockaddr_in addr = {0};

    if(!block)   //non-block
    {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);	//IPPROTO_TCP
    }
    else
    {
        fd = socket(AF_INET, SOCK_STREAM, 0);
    }

    if(fd == -1)
    {
        return fd;
    }

    if(reuse)   //set reuse
    {
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &SOCKET_REUSE_FLAG, sizeof(SOCKET_REUSE_FLAG));
    }

    //bind socket
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=INADDR_ANY;
    addr.sin_port = htons(port);
    bind(fd,(__CONST_SOCKADDR_ARG)(&addr),sizeof(addr));
    //listen socket
    listen(fd,SOMAXCONN);

    return fd;
}

static int create_reqSocket(int port,int reuse,int block)
{
    return socket_tunneld(port,reuse,block);
}

static char *recv_noBlockSocket(int fd,int *recv_len)
{
    char *data = NULL;
    int dlen = 0;
    char buff[RECV_BUFF_SIZE];
    int ret = 0;
    int recv_cnt = 0;   //recv count

    do
    {
        ret = recv(fd,buff,RECV_BUFF_SIZE,0);
        // LOG_DEBUG("fd %d recv data result %d,errno %d",fd,ret,errno);
        if(ret == 0)    //socket closed
        {
            //TODO:handle socket closed event
            break;
        }
        else if(ret == -1)
        {
            if(!(EAGAIN == errno || EINTR == errno))
            {
                //TODO:handle unnormal close socket event
                break;
            }
            else if(EAGAIN == errno && recv_cnt++>10)
            {
                LOG_DEBUG("### recv error EAGAIN break");
                break;
            }
        }
        else if(ret > 0)
        {
            if(data == NULL && dlen == 0)
            {
                data = malloc(ret);
                assert(data!=NULL);
                memcpy(data,buff,ret);
                dlen = ret;
            }
            else if(data != NULL && dlen > 0)
            {
                char *tmp = NULL;

                tmp = malloc(dlen + ret);
                assert(tmp!=NULL);
                memcpy(tmp,data,dlen);
                memcpy(tmp+dlen,buff,ret);
                free(data);
                data = tmp;
                dlen = dlen + ret;
            }
        }
    }
    while(ret>0);
    *recv_len = dlen;
    return data;
}
//************** socket operation end **************

//************** tunneld fd operation start **************
static int init_tfd_withData(pTUNNELD_FD ptfd,int fd,TUNNELD_FD_TYPE type,
                             char *data,int dlen)
{
    assert(ptfd!=NULL);
    memset(ptfd,0,sizeof(TUNNELD_FD));
    ptfd->fd = fd;
    ptfd->fd_type = type;
    if(data != NULL && dlen > 0)
    {
        ptfd->data = malloc(dlen);
        assert(ptfd->data != NULL);
        memcpy(ptfd->data,data,dlen);
        ptfd->dlen = dlen;
    }
    else
    {
        ptfd->data = NULL;
        ptfd->dlen = 0;
    }
    return 0;
}

static int init_tfd(pTUNNELD_FD ptfd,int fd,TUNNELD_FD_TYPE type)
{
    return init_tfd_withData(ptfd,fd,type,NULL,0);
}

static pTUNNELD_FD create_tfd_withData(int fd,TUNNELD_FD_TYPE type,char *data,int dlen)
{
    pTUNNELD_FD ptfd=NULL;
    ptfd = malloc(sizeof(TUNNELD_FD));
    assert(ptfd!=NULL);
    init_tfd_withData(ptfd,fd,type,data,dlen);
    return ptfd;
}

static pTUNNELD_FD create_tfd(int fd,TUNNELD_FD_TYPE type)
{
    pTUNNELD_FD ptfd=NULL;
    ptfd = malloc(sizeof(TUNNELD_FD));
    assert(ptfd!=NULL);
    init_tfd(ptfd,fd,type);
    return ptfd;
}

//free tunneld socket fd malloc memory
static void *deInit_tfd(void *_ptfd)
{
    pTUNNELD_FD ptfd = (pTUNNELD_FD)_ptfd;

    if(ptfd==NULL)
    {
        return NULL;
    }
    ptfd->fd = INVALID_SOCKET_FD;
    ptfd->fd_type = TUNNELD_FD_NOT_SET;
    if(ptfd->data != NULL)
    {
        free(ptfd->data);
        LOG_DEBUG("free %p,data length %d",ptfd->data,ptfd->dlen);
        ptfd->data = NULL;
        ptfd->dlen = 0;
    }
    return _ptfd;
}

//send tunneld fd data
static int send_tfdDate(int epfd,pTUNNELD_FD ptfd)
{
    int send_ret = 0;
    if(ptfd->data != NULL && ptfd->dlen > 0)
    {
        send_ret = send(ptfd->fd,ptfd->data,ptfd->dlen,0);
        //PRINT_RECV_DATA(ptfd->data,ptfd->dlen,1);
        LOG_DEBUG("send socket fd(%d) data %d bytes result %d",ptfd->fd,ptfd->dlen,send_ret);
        if(send_ret == -1 || send_ret == 0)
        {
            modify_epoll_tfd(epfd,ptfd->fd,ptfd);   //re-generate EPOLLOUT
        }
        else if(send_ret == ptfd->dlen)
        {
            free(ptfd->data);
            ptfd->data = NULL;
            ptfd->dlen = 0;
        }
        else if(send_ret > 0)
        {
            char* tmp = NULL;
            int rlen = 0;   //remain data length

            rlen = ptfd->dlen-send_ret;
            tmp = malloc(rlen);
            assert(tmp!=NULL);
            memcpy(tmp,ptfd->data+send_ret,rlen);
            free(ptfd->data);
            ptfd->data = tmp;
            ptfd->dlen = rlen;
            modify_epoll_tfd(epfd,ptfd->fd,ptfd);   //re-generate EPOLLOUT
        }
    }
    return 0;
}
//************** tunneld fd operation end ***************

//************** tunneld fd pair operation start **************
//initial tunneld fd pair
static int init_tfdp(pTUNNELD_FD_PAIR ptfdp,int ptfdp_size)
{
    int i;

    for(i=0; i<ptfdp_size; i++)
    {
        init_tfd(&ptfdp[i].tfd_resp,INVALID_SOCKET_FD,TUNNELD_FD_NOT_SET);
        init_tfd(&ptfdp[i].tfd_req,INVALID_SOCKET_FD,TUNNELD_FD_NOT_SET);
    }
}

static void *deinit_tfdp(void *_ptfdp)
{
    pTUNNELD_FD_PAIR ptfdp = (pTUNNELD_FD_PAIR)_ptfdp;
    int i;

    if(ptfdp==NULL)
    {
        return NULL;
    }
    for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
    {
        deInit_tfd(&ptfdp[i].tfd_req);
        deInit_tfd(&ptfdp[i].tfd_resp);
    }
    return _ptfdp;
}

//get pointer of request/response tunnel fd pair by pointer of tunnel socket fd
static pTUNNELD_FD_PAIR get_ptfdp_by_ptfd(pTUNNELD_GNL_LINK llst,pTUNNELD_FD filter_ptfd)
{
    int i;
    pTUNNELD_GNL_LINK link;
    pTUNNELD_FD_SET ptfds = NULL;
    pTUNNELD_FD_PAIR  ptfdp = NULL;

    assert(llst!=NULL);
    assert(filter_ptfd!=NULL);
    link = llst->next;    /*first tfd set is empty*/
    //LOG_DEBUG("filter_ptfd(%p) type(%d):%s",filter_ptfd,filter_ptfd->fd_type,DEBUG_TUNNELD_FD_TYPE_STR[filter_ptfd->fd_type]);
    while(link)
    {
        ptfds = link->data;
        ptfdp = ptfds->tfd_pair;
        //LOG_DEBUG("link %p,tunneld fd pair %d",link,ptfds->tfd_pairNum);
        for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
        {
            //LOG_DEBUG("pair index %d,request pointer %p,respone pointer %p",i,&ptfdp[i].tfd_req,&ptfdp[i].tfd_resp);
            if(filter_ptfd->fd_type == TUNNELD_FD_RESP_CONN && filter_ptfd == &ptfdp[i].tfd_resp)
            {
                return &ptfdp[i];
            }
            else if(filter_ptfd->fd_type == TUNNELD_FD_REQ_CONN && filter_ptfd == &ptfdp[i].tfd_req)
            {
                return &ptfdp[i];
            }
        }
        link = link->next;
    }
    return NULL;
}

static pTUNNELD_FD_PAIR get_noReq_tfdp(TUNNELD_FD_PAIR tfd_pair[MAX_REQ_RESP_CONN_PAIR])
{
    int i;

    for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
    {
        if(tfd_pair[i].tfd_req.fd == INVALID_SOCKET_FD)
        {
            return &tfd_pair[i];
        }
    }
    return NULL;
}

static pTUNNELD_FD_PAIR get_ptfdp_by_reqfd(pTUNNELD_FD_SET ptfds,int req_fd)
{
    int i;
    for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
    {
        if(ptfds->tfd_pair[i].tfd_req.fd == req_fd)
        {
            if(ptfds->tfd_pair[i].tfd_resp.fd == INVALID_SOCKET_FD)
            {
                return &ptfds->tfd_pair[i];
            }
            else
            {
                LOG_INFO("Note:already exist response socket,error occur...");
                return NULL;
            }
        }
    }
    return NULL;
}


//************** tunneld fd pair operation end **************

//************** tunneld fd set operation start ***************
static int init_tfds(pTUNNELD_FD_SET ptfds)
{
    if(ptfds==NULL)
    {
        return 0;
    }
    init_tfd(&ptfds->tfd_mgt,INVALID_SOCKET_FD,TUNNELD_FD_NOT_SET);
    init_tfd(&ptfds->tfd_reqListen,INVALID_SOCKET_FD,TUNNELD_FD_NOT_SET);
    init_tfdp(ptfds->tfd_pair,MAX_REQ_RESP_CONN_PAIR);
    ptfds->tfd_pairNum = 0;
    memset(ptfds->token,0,TOKEN_LENGTH);
    ptfds->data=NULL;
    ptfds->dlen=0;
    return 0;
}
static pTUNNELD_FD_SET create_tfds()
{
    pTUNNELD_FD_SET ptfds=NULL;

    ptfds = malloc(sizeof(TUNNELD_FD_SET));
    assert(ptfds!=NULL);
    init_tfds(ptfds);
    return ptfds;
}

static pTUNNELD_FD_SET get_ptfds_by_ptfd(pTUNNELD_GNL_LINK llst,pTUNNELD_FD filter_ptfd)
{
    pTUNNELD_GNL_LINK link;
    pTUNNELD_FD_SET ptfds = NULL;
    pTUNNELD_FD_PAIR ptfdp = NULL; //pointer tunneld fd pair
    int i=0;

    assert(llst!=NULL);
    assert(filter_ptfd!=NULL);
    link = llst->next;    /*first tfd set is empty*/
    //LOG_DEBUG("filter ptfd %p,tunneld socket type %d",filter_ptfd,filter_ptfd->fd_type);
    while(link)
    {
        ptfds = link->data;
        ptfdp = ptfds->tfd_pair;
        if(filter_ptfd->fd_type == TUNNELD_FD_NOT_SET)
        {
            LOG_INFO("failed get tunneld socket fd set,filter tunneld fd type is %s,must pass token to get tunnel fd set"
                     ,DEBUG_TUNNELD_FD_TYPE_STR[filter_ptfd->fd_type]);
            return NULL;
        }
        if(filter_ptfd->fd_type == TUNNELD_FD_MGNT_LISTENING)   /* type is TUNNELD_FD_MGNT_LISTENING,use token */
        {
            //LOG_INFO("failed get tunneld socket fd set,filter tunneld fd type is TUNNELD_FD_MGNT_LISTENING,must pass token to get tunnel fd set");
            LOG_INFO("failed get tunneld socket fd set,filter tunneld fd type is %s",DEBUG_TUNNELD_FD_TYPE_STR[filter_ptfd->fd_type]);
            return NULL;
        }
        else if(filter_ptfd->fd_type == TUNNELD_FD_MGNT_CONN && (&(ptfds->tfd_mgt) == filter_ptfd))
        {
            return ptfds;
        }
        else if(filter_ptfd->fd_type == TUNNELD_FD_RESP_CONN)
        {
            for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
            {
                if(filter_ptfd == &(ptfdp[i].tfd_resp))
                {
                    return ptfds;
                }
            }
        }
        else if(filter_ptfd->fd_type == TUNNELD_FD_REQ_LISTENING && (&(ptfds->tfd_reqListen) == filter_ptfd))
        {
            return ptfds;
        }
        else if(filter_ptfd->fd_type == TUNNELD_FD_REQ_CONN)
        {
            for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
            {
                if(filter_ptfd == &(ptfdp[i].tfd_req))
                {
                    return ptfds;
                }
            }
        }
        link = link->next;
    }
    return NULL;
}

static pTUNNELD_FD_SET get_ptfds_by_token(pTUNNELD_GNL_LINK llst,char *token)
{
    pTUNNELD_GNL_LINK link;
    pTUNNELD_FD_SET ptfds = NULL;

    assert(llst!=NULL);
    assert(token!=NULL);
    link = llst->next;    /*first tfd set is empty*/
    while(link)
    {
        ptfds = link->data;
        if((ptfds!=NULL) && (strlen(ptfds->token)>0) && (strcmp(ptfds->token,token) == 0))
        {
            return ptfds;
        }
        link = link->next;
    }
    return NULL;
}

void *free_ptfds(void *_ptfds)
{
    pTUNNELD_FD_SET ptfds = (pTUNNELD_FD_SET)_ptfds;
    int i=0;

    if(ptfds==NULL)
    {
        return NULL;
    }
    deInit_tfd(&ptfds->tfd_mgt);
    deInit_tfd(&ptfds->tfd_reqListen);
    deinit_tfdp(ptfds->tfd_pair);
    ptfds->tfd_pairNum = 0;
    memset(ptfds->token,0,TOKEN_LENGTH);
    if(ptfds->data)
    {
        free(ptfds->data);
        ptfds->data = NULL;
    }
    ptfds->dlen = 0;
    return _ptfds;
}
//************** tunneld fd set operation end ***************

//************** link list operation start **************
static int add_data_to_llst(pTUNNELD_GNL_LINK llst,void *data)
{
    pTUNNELD_GNL_LINK tail = llst;
    pTUNNELD_GNL_LINK temp;
    if(llst == NULL)
    {
        LOG_INFO("NULL link list,add tunneld fd set failed!");
        return 0;
    }

    while(tail->next != NULL)   //get link list tail
    {
        tail = tail->next;
    }
    temp = malloc(sizeof(TUNNELD_GNL_LINK));
    assert(temp != NULL);
    temp->data=data;
    temp->next = NULL;
    tail->next = temp;
    return 0;
}

static int free_llst(pTUNNELD_GNL_LINK llst,FREE_LLST_DATA_FUN freeData_cb)
{
    pTUNNELD_GNL_LINK next = NULL,temp;

    if(llst == NULL)
    {
        return 0;
    }
    next = llst->next;  //first link not used
    while(next)
    {
        if(next->data && freeData_cb)
        {
            freeData_cb(next->data);
            free(next->data);
            next->data = NULL;
        }
        temp = next->next;
        free(next);
        next = temp;
    }
    llst->next = NULL;
    return 0;
}

static int get_llstNum(pTUNNELD_GNL_LINK llst)
{
    int cnt = 0;
    pTUNNELD_GNL_LINK pnext;

    if(llst == NULL)
    {
        return 0;
    }
    pnext = llst->next;  //first link not used
    while(pnext)
    {
        cnt++;
        pnext = pnext->next;
    }
    return cnt;
}

static int remove_data_from_llst(pTUNNELD_GNL_LINK llst,void *data,FREE_LLST_DATA_FUN freeData_cb)
{
    pTUNNELD_GNL_LINK tld_link = NULL,pre_link = NULL;
    pTUNNELD_FD cmp_tfd = NULL;

    if(data == NULL)
    {
        return 0;
    }
    tld_link = llst->next;    /*first tfd set is empty*/
    assert(tld_link!=NULL);
    pre_link = llst;
    while(tld_link)
    {
        if(data == tld_link->data)
        {
            if(freeData_cb)
            {
                freeData_cb(tld_link->data);
                free(tld_link->data);
                tld_link->data = NULL;
            }
            pre_link->next = tld_link->next;
            free(tld_link);
            return 0;
        }
        pre_link = tld_link;
        tld_link = tld_link->next;
    }
    return 1;
}
//************** link list operation end **************

void _sighandler_t(int sig)
{
    LOG_INFO("tunneld fd chain length %d",get_llstNum(&g_tfds_llst));
    free_llst(&g_tfds_llst,free_ptfds);
    LOG_INFO("tunneld fd chain length %d",get_llstNum(&g_tfds_llst));
    LOG_INFO("ctrl+c program");
    zlog_fini();
    exit(0);
}

//************** epoll operation start **************
//re-register epollout to send data
static int reRegEpout(int epfd,pTUNNELD_FD ptfd,char *data,int dlen)
{
    struct epoll_event ev;
    int length = 0,pos = 0;
    char *tmp = NULL;

    assert(dlen>0);
    length = dlen;
    if(ptfd->data != NULL)
    {
        LOG_INFO("socket fd %d remain %d bytes data",ptfd->fd,ptfd->dlen);
        assert(ptfd->dlen > 0);
        length += ptfd->dlen;
    }
    tmp = malloc(length);
    assert(tmp!=NULL);
    if(ptfd->data != NULL)
    {
        memcpy(tmp,ptfd->data,ptfd->dlen);
        pos = ptfd->dlen;
        free(ptfd->data);
    }
    memcpy(tmp+pos,data,dlen);
    ptfd->data = tmp;
    ptfd->dlen = length;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
    ev.data.ptr=(void *)ptfd;
    epoll_ctl(epfd, EPOLL_CTL_MOD,ptfd->fd, &ev);
    return 0;
}

static int add_fd_to_epoll(int epfd,int fd,void *epoll_ptr)
{
    struct epoll_event ev;

    ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = epoll_ptr;
    epoll_ctl(epfd,EPOLL_CTL_ADD,fd,&ev);
    return 0;
}

static int modify_epoll_tfd(int epfd,int fd,void *epoll_ptr)    //only triger EPOLLOUT
{
    struct epoll_event ev;

    ev.events = EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP;
    ev.data.ptr=epoll_ptr;
    epoll_ctl(epfd, EPOLL_CTL_MOD,fd, &ev);
    return 0;
}
//************** epoll operation end **************

static int add_inListenEvNewConn(int epfd,pTUNNELD_FD ptfd,char *data,int len)
{
    int req_listenfd = INVALID_SOCKET_FD;
    int req_listenPort = -1;
    struct sockaddr_in req_addr= {0};
    socklen_t req_len;
    pTUNNELD_FD_SET ptfds;
    char token[TOKEN_LENGTH] = {0};
    char cmd[TUNNELD_CMD_LENGTH] = {0};
    char pwd[TUNNELD_CMD_LENGTH] = {0};
    int mgt_fd = ptfd->fd;

    assert(data!=NULL);
    sscanf(data,"%s %s",cmd,pwd);
    if(strcmp(pwd,TUNNEL_PASSWD) != 0)   //check password
    {
        LOG_INFO("new tunnel connection password error,close socket fd %d",mgt_fd);
        sprintf(cmd,"%s %s\n",TUNNELD_LISTENING_MSG_PULL_CMD,CONN_TUNNELD_PASSWD_ERROR);
        send(mgt_fd,cmd,strlen(cmd)+1,0);
        epoll_ctl(epfd, EPOLL_CTL_DEL,mgt_fd,NULL);
        close(mgt_fd);
        return 0;
    }
    //create a listening socket to receive request.
    req_listenfd = create_reqSocket(0,SOCKET_NO_REUSE,SOCKET_NO_BLOCK);
    DBUG_SOCK_INFO(req_listenfd);
    req_len = sizeof(struct sockaddr_in);
    getsockname(req_listenfd, (struct sockaddr *) &req_addr, &req_len);
    req_listenPort = ntohs(req_addr.sin_port);
    LOG_NOTICE("request port %d",req_listenPort);
    //create tunneld socket fd set
    ptfds = create_tfds();
    //generate string including token and port
    gen_randStr(token,TOKEN_LENGTH);    //generate random string as token
    memcpy(ptfds->token,token,sizeof(token));
    sprintf(cmd,"%s %s port %d token %s\n",TUNNELD_LISTENING_MSG_PULL_CMD,CONN_TUNNELD_PASSWD_SUCCESS,req_listenPort,token);
    //init mgnt fd
    init_tfd_withData(&(ptfds->tfd_mgt),ptfd->fd,TUNNELD_FD_MGNT_CONN,cmd,strlen(cmd));
    //modify not set socket fd to manage socket fd
    modify_epoll_tfd(epfd,ptfd->fd,(void *)&(ptfds->tfd_mgt));
    //add request socket fd to tunnel socket fd set
    init_tfd(&(ptfds->tfd_reqListen),req_listenfd,TUNNELD_FD_REQ_LISTENING);
    //add request fd to epoll
    add_fd_to_epoll(epfd,req_listenfd,(void *)&(ptfds->tfd_reqListen));
    //add to global link list
    add_data_to_llst(&g_tfds_llst,(void *)ptfds);
    return 0;
}

static int pull_inListenEvTfdp(int epfd,pTUNNELD_FD ptfd,char *data,int len)
{
    pTUNNELD_FD_SET ptfds=NULL;
    char cmd[TUNNELD_CMD_LENGTH] = {0};
    char token[TUNNELD_CMD_LENGTH] = {0};
    int req_fd = INVALID_SOCKET_FD;
    int i=0;
    pTUNNELD_FD_PAIR ptfdp = NULL;

    assert(data!=NULL);
    sscanf(data,"%s %s %d",cmd,token,&req_fd);
    LOG_INFO("request socket fd %d",req_fd);
    ptfds = get_ptfds_by_token(&g_tfds_llst,token);
    assert(ptfds!=NULL);
    ptfdp = get_ptfdp_by_reqfd(ptfds,req_fd);
    if(ptfdp != NULL)
    {
        add_fd_to_epoll(epfd,req_fd,&ptfdp->tfd_req);   //add request fd to epoll
        if(ptfdp->tfd_resp.fd == INVALID_SOCKET_FD)
        {
            ptfdp->tfd_resp.fd = ptfd->fd;
            init_tfd(&(ptfdp->tfd_resp),ptfd->fd,TUNNELD_FD_RESP_CONN);
            modify_epoll_tfd(epfd,ptfd->fd,&ptfdp->tfd_resp);
            LOG_DEBUG("tunneld fd pair,request fd(%d),response fd(%d)",ptfdp->tfd_req.fd,ptfdp->tfd_resp.fd);
            ptfds->tfd_pairNum++;
            LOG_INFO("request response pair number %d",ptfds->tfd_pairNum);
        }
        else
        {
            LOG_DEBUG("alread exist repsonse fd,close fd %d",ptfd->fd);
            close(ptfd->fd);
        }
    }
    return 0;
}

static int handle_closeEv(int epfd,pTUNNELD_FD ptfd)
{
    pTUNNELD_FD_SET ptfds = NULL;
    pTUNNELD_FD_PAIR pReqRespPair = NULL;

    epoll_ctl(epfd, EPOLL_CTL_DEL,ptfd->fd,NULL);
    close(ptfd->fd);
    LOG_DEBUG("close socket fd %d,socket type %s",ptfd->fd,DEBUG_TUNNELD_FD_TYPE_STR[ptfd->fd_type]);
    ptfds = get_ptfds_by_ptfd(&g_tfds_llst,ptfd);
    switch(ptfd->fd_type)
    {
        case TUNNELD_FD_NOT_SET:
            free(ptfd);/* free TUNNELD_FD_NOT_SET ptfd here */
            goto HANDLE_FD_NOT_SET;
            break;
        case TUNNELD_FD_MGNT_LISTENING:
            break;
        case TUNNELD_FD_MGNT_CONN:
            //TODO:
            break;
        case TUNNELD_FD_RESP_CONN:
            pReqRespPair = get_ptfdp_by_ptfd(&g_tfds_llst,ptfd);
            //close request socket,because response socket closed
            if(pReqRespPair->tfd_req.fd !=INVALID_SOCKET_FD)
            {
                close(pReqRespPair->tfd_req.fd);
                LOG_INFO("close request socket fd:%d,due to response socket fd %d closed",pReqRespPair->tfd_req.fd,ptfd->fd);
                epoll_ctl(epfd, EPOLL_CTL_DEL,pReqRespPair->tfd_req.fd,NULL);
                deInit_tfd(&pReqRespPair->tfd_req);
            }
            ptfds->tfd_pairNum--;
            LOG_INFO("remove pair sockets due to response socekt closed,remain %d pair sockets",ptfds->tfd_pairNum);
            break;
        case TUNNELD_FD_REQ_LISTENING:
            break;
        case TUNNELD_FD_REQ_CONN:
            pReqRespPair = get_ptfdp_by_ptfd(&g_tfds_llst,ptfd);
            if(pReqRespPair->tfd_resp.fd ==INVALID_SOCKET_FD)
            {
                ptfds->tfd_pairNum--;
                LOG_INFO("remove pair sockets due to request socekt closed,remain %d pair sockets",ptfds->tfd_pairNum);
            }
            break;
        default:
            break;
    }
    deInit_tfd(ptfd);
    if(ptfds->tfd_mgt.fd == INVALID_SOCKET_FD && ptfds->tfd_pairNum == 0)   //management socekt closed
    {
        //LOG_DEBUG("remove tunnel fd set(%p) from link list,remain %d tunneld fd set",ptfds,get_llstNum(&g_tfds_llst));
        close(ptfds->tfd_reqListen.fd);
        deInit_tfd(&ptfds->tfd_reqListen);
        remove_data_from_llst(&g_tfds_llst,ptfds,free_ptfds);
        LOG_DEBUG("remove tunnel fd set(%p) from link list,remain %d tunneld fd set",ptfds,get_llstNum(&g_tfds_llst));
    }
HANDLE_FD_NOT_SET:
    return 0;
}

static int handle_inNotSetTypeEv(int epfd,pTUNNELD_FD ptfd)
{
    char *recv_data = NULL;
    int recv_dlen = 0;
    TUNNELD_LISTENING_MSG_TYPE msg_type = TUNNELD_LISTENING_MSG_NOT_SET;

    recv_data = recv_noBlockSocket(ptfd->fd,&recv_dlen);
    if(recv_data == NULL)
    {
        LOG_DEBUG("no data received from socket fd %d",ptfd->fd);
        return 0;
    }
    msg_type = get_ListenMsgType(recv_data,recv_dlen);
    //PRINT_RECV_DATA(recv_data,recv_dlen,0);
    LOG_DEBUG("received %d bytes recv_data from fd %d,mgnt msg type %d",recv_dlen,ptfd->fd,msg_type);
    switch(msg_type)
    {
        case TUNNELD_LISTENING_MSG_CHK_PWD:
            add_inListenEvNewConn(epfd,ptfd,recv_data,recv_dlen);
            free(ptfd);
            break;
        case TUNNELD_LISTENING_MSG_PULL:
            pull_inListenEvTfdp(epfd,ptfd,recv_data,recv_dlen);
            free(ptfd);
            break;
        default:    //close unknown connected socket
            //close(ptfd->fd);
            //epoll_ctl(epfd, EPOLL_CTL_DEL,ptfd->fd,NULL);
            //deInit_tfd(ptfd);
            //free(ptfd);
            break;
    }
    //free(ptfd); /* free TUNNELD_FD_NOT_SET ptfd here */
    return 0;
}

static int handle_inMgntListenEv(int epfd,pTUNNELD_FD ptfd)
{
    struct sockaddr_in acpt_addr= {0};
    socklen_t acpt_len = 0;
    int acpt_fd = 0;;
    pTUNNELD_FD new_ptfd = NULL;

    memset(&acpt_addr,0,sizeof(acpt_addr));
    //accept tunneld socket fd
    acpt_len = sizeof(acpt_addr);
    while(1)
    {
        acpt_fd = accept(ptfd->fd,(__SOCKADDR_ARG)&acpt_addr,&acpt_len);
        if(!(acpt_fd > 0))
        {
            if(acpt_fd == -1)
            {
                if (errno != EAGAIN &&errno != ECONNABORTED
                        &&errno != EPROTO &&errno != EINTR)
                {
                    LOG_NOTICE("accept errno:%d",errno);
                    perror("accept");
                }
            }
            break;
        }
        set_noblockSock(acpt_fd);
        //DBUG_PEER_SOCK_INFO(acpt_fd);
        //DBUG_SOCK_INFO(acpt_fd);
        new_ptfd = create_tfd(acpt_fd,TUNNELD_FD_NOT_SET);
        add_fd_to_epoll(epfd,acpt_fd,new_ptfd);
    }
    //TODO:create a link list to save not set type socket
    return 0;
}

static int handle_inReqListenEv(int epfd,pTUNNELD_FD ptfd)
{
    struct sockaddr_in acpt_addr= {0};
    socklen_t acpt_len = 0;
    int req_fd = 0;
    pTUNNELD_FD_SET ptfds=NULL;
    char cmd_data[TUNNELD_CMD_DATA_LENGTH] = {0};
    int i;
    pTUNNELD_FD_PAIR ptfdp = NULL;

    ptfds = get_ptfds_by_ptfd(&g_tfds_llst,ptfd);
    if(ptfds == NULL)
    {
        LOG_INFO("get tunneld socekt fd set failed");
        return 0;
    }
    acpt_len = sizeof(acpt_addr);

    while(1)
    {
        req_fd = accept(ptfd->fd,(__SOCKADDR_ARG)&acpt_addr,&acpt_len);
        if(!(req_fd > 0))
        {
            if(req_fd == -1)
            {
                if (errno != EAGAIN &&errno != ECONNABORTED
                        &&errno != EPROTO &&errno != EINTR)
                {
                    LOG_NOTICE("accept errno:%d",errno);
                    perror("accept");
                }
            }
            break;
        }
        //DBUG_PEER_SOCK_INFO(req_fd);
        //DBUG_SOCK_INFO(req_fd);
        set_noblockSock(req_fd);

        ptfdp = get_noReq_tfdp(ptfds->tfd_pair);
        if(ptfdp!=NULL)
        {
            init_tfd(&ptfdp->tfd_req,req_fd,TUNNELD_FD_REQ_CONN);
            if(ptfdp->tfd_resp.fd == INVALID_SOCKET_FD)
            {
                sprintf(cmd_data,"%s %d\n",TUNNELD_REQUEST_STR,req_fd);
                LOG_DEBUG("%s",cmd_data);
                reRegEpout(epfd,&(ptfds->tfd_mgt),cmd_data,strlen(cmd_data));
            }
            else
            {
                LOG_DEBUG("already exist response socket fd(%d),match request fd(%d)",ptfdp->tfd_resp.fd,req_fd);
                add_fd_to_epoll(epfd,req_fd,&ptfdp->tfd_req);
            }
            continue;
        }
        LOG_INFO("###close fd %d,",req_fd);
        close(req_fd);
    }
    return 0;
}

static int handle_inMgntEv(int epfd,pTUNNELD_FD ptfd)
{
#if 1
    char *recv_data = NULL;
    int recv_dlen = 0;
    TUNNELD_LISTENING_MSG_TYPE msg_type = TUNNELD_LISTENING_MSG_NOT_SET;

    recv_data = recv_noBlockSocket(ptfd->fd,&recv_dlen);
    if(recv_data == NULL)
    {
        LOG_DEBUG("no data received from socket fd %d",ptfd->fd);
        return 0;
    }
    PRINT_RECV_DATA(recv_data,recv_dlen,1); //should receive heart beat...
    free(recv_data);
    return 0;
#endif
}

static int handle_inReqEv(int epfd,pTUNNELD_FD ptfd)
{
    char *recv_data = NULL;
    int recv_dlen = 0;
    pTUNNELD_FD_PAIR ptReqResp= NULL;

    ptReqResp = get_ptfdp_by_ptfd(&g_tfds_llst,ptfd);
    assert(ptReqResp!=NULL);

    recv_data = recv_noBlockSocket(ptfd->fd,&recv_dlen);
    LOG_DEBUG("received %d bytes recv_data from fd %d,type TUNNELD_FD_REQ_CONN",recv_dlen,ptfd->fd);
    if(recv_data!=NULL)
    {
        //PRINT_RECV_DATA(recv_data,recv_dlen,1);
        if(ptReqResp->tfd_resp.fd != INVALID_SOCKET_FD)
        {
            reRegEpout(epfd,&(ptReqResp->tfd_resp),recv_data,recv_dlen);  //send received data to response socket fd
        }
        else
        {
            //TODO:change add epoll position
            //init_tfd_withData(&ptReqResp->tfd_resp,INVALID_SOCKET_FD,TUNNELD_FD_RESP_CONN,recv_data,recv_dlen);
            //LOG_DEBUG("###request socket fd(%d) has no response socket fd",ptfd->fd);
        }
        free(recv_data);
        recv_data = NULL;
    }
    return 0;
}

static int handle_inRespEv(int epfd,pTUNNELD_FD ptfd)
{
    char *recv_data = NULL;
    int recv_dlen = 0;
    pTUNNELD_FD_PAIR ptReqResp= NULL;

    ptReqResp = get_ptfdp_by_ptfd(&g_tfds_llst,ptfd);
    assert(ptReqResp!=NULL);
    if(ptReqResp->tfd_req.fd == INVALID_SOCKET_FD)
    {
        return 0;
    }
    recv_data = recv_noBlockSocket(ptfd->fd,&recv_dlen);
    LOG_DEBUG("received %d bytes recv_data from fd %d,type TUNNELD_FD_RESP_CONN",recv_dlen,ptfd->fd);
    if(recv_data != NULL)
    {
        //PRINT_RECV_DATA(recv_data,recv_dlen,1);
        reRegEpout(epfd,&(ptReqResp->tfd_req),recv_data,recv_dlen);  //send received recv_data to request socket fd
        free(recv_data);
        recv_data = NULL;
    }
    return 0;
}

static int handle_outMgntConnEv(int epfd,pTUNNELD_FD mgnt_ptfd)
{
    return send_tfdDate(epfd,mgnt_ptfd);
}

static int handle_outReqConnEv(int epfd,pTUNNELD_FD req_ptfd)
{
    return send_tfdDate(epfd,req_ptfd);
}

static int handle_outRespConnEv(int epfd,pTUNNELD_FD resp_ptfd)
{
    return send_tfdDate(epfd,resp_ptfd);
}

#ifdef USE_INI_CONF
static int tunneld_load_iniConfig()
{
    dictionary *ini;
    const char *p_lst_port = NULL;
    const char *p_conn_pwd = NULL;
    const char *p_zlog_conf_path = NULL;

    ini = iniparser_load(TUNNELD_CONFIG_FILE);
    p_lst_port = iniparser_getstring(ini, "config:port", DEFAULT_TUNNELD_LISTEN_PORT);
    p_conn_pwd=iniparser_getstring(ini, "config:password",DEFAULT_TUNNELD_PASSWD);
    p_zlog_conf_path = iniparser_getstring(ini, "config:zlog_conf",DEFAULT_TUNNELD_ZLOG_CONFIG_FILE);
    TUNNLED_LISTEN_PORT = atoi(p_lst_port);
    sprintf(TUNNEL_PASSWD,"%s",p_conn_pwd);
    sprintf(ZLOG_CONFIG_FILE,"%s",p_zlog_conf_path);
    iniparser_freedict(ini);
    return 0;
}

#endif

int main(int argc,void *args)
{
    int fd;
    int epfd;
    struct epoll_event ev,event[MAX_EVENT];
    int ecnt;   //event count
    pTUNNELD_FD ptfd_listen;
    pTUNNELD_FD ptfd;

    // signal(SIGTTOU, SIG_IGN);
    // signal(SIGTTIN, SIG_IGN);
    // signal(SIGHUP, SIG_IGN);
#ifdef USE_INI_CONF
    tunneld_load_iniConfig();
#endif
    signal(SIGPIPE, SIG_IGN);   /* catch signal while socket close */
    signal(SIGINT, _sighandler_t);
    //printf("tunneld listening port:%d,password:%s,configure file:%s\r\n",TUNNLED_LISTEN_PORT,TUNNEL_PASSWD,ZLOG_CONFIG_FILE);
    dzlog_init(ZLOG_CONFIG_FILE,"tunneld");
    LOG_INFO("tunneld listening port:%d,password:%s,configure file:%s",TUNNLED_LISTEN_PORT,TUNNEL_PASSWD,ZLOG_CONFIG_FILE);
    //create tunneld socket to listen
    fd = socket_tunneld(TUNNLED_LISTEN_PORT,SOCKET_REUSE,SOCKET_NO_BLOCK); //SOCKET_BLOCK SOCKET_NO_BLOCK
    //create epoll
    epfd = epoll_create1(0);
    memset(&ev,0,sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;  //Edge triggered,triggered only when data is written from the peer
    ptfd_listen = malloc(sizeof(TUNNELD_FD));
    assert(ptfd_listen!=NULL);
    memset(ptfd_listen,0,sizeof(TUNNELD_FD));
    ptfd_listen->fd = fd;
    ptfd_listen->fd_type = TUNNELD_FD_MGNT_LISTENING;
    ev.data.ptr = (void *)ptfd_listen;
    //set epoll
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    //start epoll wait
    while(1)
    {
        int i;
        ecnt = epoll_wait(epfd, event, MAX_EVENT, -1);
        //LOG_INFO("epoll event count %d",ecnt);
        for(i=0; i<ecnt; i++)
        {
            ptfd = (TUNNELD_FD *)event[i].data.ptr;
            LOG_DEBUG("epoll event 0x%02x,fd %d,socket fd type %s",event[i].events,ptfd->fd,DEBUG_TUNNELD_FD_TYPE_STR[ptfd->fd_type]);

            /* socket close event */
            if(event[i].events & EPOLLRDHUP)    /* same system may not trigger EPOLLRDHUP */
            {
                //handle socket close event
                handle_closeEv(epfd,ptfd);
                continue;
            }

            //new connection from peer socket,or new data come from peer socket
            if(event[i].events & EPOLLIN)
            {
                // LOG_DEBUG("ptfd->fd_type:%d",ptfd->fd_type);
                if(ptfd->data != NULL && ptfd->dlen > 0)  //skip EPOLLIN event,due to still remain data to handle
                {
                    LOG_DEBUG("socket fd %d remain data to handle,skip EPOLLIN event.",ptfd->fd);
                    DBUG_SOCK_INFO(ptfd->fd);
                }
                else
                {
                    switch (ptfd->fd_type)
                    {
                        case TUNNELD_FD_NOT_SET:
                            handle_inNotSetTypeEv(epfd,ptfd);
                            break;
                        case TUNNELD_FD_MGNT_LISTENING:
                            //handle mangement listening socket event
                            handle_inMgntListenEv(epfd,ptfd);
                            break;
                        case TUNNELD_FD_REQ_LISTENING:
                            //handle request listening socket event
                            handle_inReqListenEv(epfd,ptfd);
                            break;
                        case TUNNELD_FD_MGNT_CONN:
                            handle_inMgntEv(epfd,ptfd);
                            break;
                        case TUNNELD_FD_REQ_CONN:
                            handle_inReqEv(epfd,ptfd);
                            break;
                        case TUNNELD_FD_RESP_CONN:
                            handle_inRespEv(epfd,ptfd);
                            break;
                        default:
                            break;
                    }
                }
            }

            if(event[i].events & EPOLLOUT)   /* triger when: send buffer writable */
            {
                switch (ptfd->fd_type)
                {
                    case TUNNELD_FD_NOT_SET:
                    case TUNNELD_FD_MGNT_LISTENING:
                    case TUNNELD_FD_REQ_LISTENING:
                        break;
                    case TUNNELD_FD_MGNT_CONN:
                        handle_outMgntConnEv(epfd,ptfd);
                        break;
                    case TUNNELD_FD_REQ_CONN:
                        handle_outReqConnEv(epfd,ptfd);
                        break;
                    case TUNNELD_FD_RESP_CONN:
                        handle_outRespConnEv(epfd,ptfd);
                        break;
                    default:
                        break;
                }
            }
        }
        //sleep(2);
    }
    close(fd);
    return 0;
}
