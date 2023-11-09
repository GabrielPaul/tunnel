#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/select.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "tunnel.h"
#include "common.h"

#ifdef BUILD_LIBRARY_TUNNEL
static CONN_TUNNEL_CALLBACK g_conn_cb = NULL;
static CLOSE_TUNNEL_CALLBACK g_close_cb = NULL;
#else
#include "iniparser.h"

#define TUNNEL_CONFIG_FILE "./tunnel.conf"
#define DEFAULT_SERVER_ADDR "192.168.16.193"
#define DEFAULT_SERVER_PORT "8877"
#define DEFAULT_SERVER_AUTH_STR "kdgc_aron"
#define DEFAULT_LOCAL_SERVER_PORT "80"
#endif
volatile int gRunTunnel = 1;
static char TUNNELD_ADDR[64] = {0};
static int TUNNELD_PORT = 0;
static char TUNNELD_AUTH_STR[64] = {0};
static int TUNNEL_LOCAL_SERVICE_PORT = 0;

static char gtoken[TOKEN_LENGTH] = {0};
static char gReqPort[5] = {0};
static TUNNEL_FD_LINK_LIST gtfd_llst;
static TUNNEL_REQRESP_PAIR_TYPE gloTldPair[MAX_REQ_RESP_CONN_PAIR];
static int gtfdp_num = 0;

const char DEBUG_TUNNEL_FD_TYPE_STR[][64]=
{
    "TUNNEL_FD_TYPE_NOT_SET",
    "TUNNEL_FD_MGNT_TLD",
    "TUNNEL_FD_LSRV",
    "TUNNEL_FD_LSRV2TLD",
    "TUNNEL_FD_TYPE_COUNT"
};

static int close_tfd(pTUNNEL_FD ptfd);
static pTUNNEL_FD_LINK_LIST remove_tfdFromLLst(pTUNNEL_FD_LINK_LIST llst,pTUNNEL_FD ptfd);

static int append_data(char **sd,int *sd_len,char *data,int dlen)
{
    char *tmp = NULL;

    assert(sd!=NULL && sd_len!=NULL);
    assert(data != NULL && dlen > 0);
    if(*sd == NULL && *sd_len == 0)
    {
        tmp = malloc(dlen);
        assert(tmp!=NULL);
        memcpy(tmp,data,dlen);
        *sd=tmp;
        *sd_len = dlen;
        LOG_DEBUG("copy %d bytes data from %p",dlen,data);
    }
    else if(*sd != NULL && *sd_len > 0)
    {
        tmp = malloc(dlen + *sd_len);
        assert(tmp != NULL);
        memcpy(tmp,*sd,*sd_len);
        memcpy(tmp + *sd_len,data,dlen);
        free(*sd);
        *sd = tmp;
        *sd_len = dlen + *sd_len;
        LOG_DEBUG("append %d bytes data from %p,total data length %d",dlen,data,*sd_len);
    }
    return 0;
}

int getLocalIP(const char *ethernet, char *addr_ipv4, char *addr_ipv6)
{
    struct ifaddrs *ifAddrStruct = NULL;
    void *tmpAddrPtr = NULL;
    char addressBuffer[INET_ADDRSTRLEN];
    char addressBuffer6[INET6_ADDRSTRLEN];

    getifaddrs(&ifAddrStruct);
    while (ifAddrStruct != NULL)
    {
        if (ifAddrStruct->ifa_addr == NULL)
        {
            ifAddrStruct=ifAddrStruct->ifa_next;
            continue;
        }
        tmpAddrPtr = &((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
        if (ifAddrStruct->ifa_addr->sa_family == AF_INET && addr_ipv4 != NULL)   // check it is IP4
        {
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN); // is a valid IP4 Address
            // printf("%s IP Address %s\n", ifAddrStruct->ifa_name, addressBuffer);
            if(ethernet!=NULL)
            {
                if(strcmp(ifAddrStruct->ifa_name, ethernet) == 0)
                {
                    strcpy(addr_ipv4, addressBuffer);
                }
            }
            else
            {
                strcpy(addr_ipv4, addressBuffer);
            }
        }
        else if (ifAddrStruct->ifa_addr->sa_family == AF_INET6 && addr_ipv6 != NULL)     // check it is IP6
        {
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer6, INET6_ADDRSTRLEN); // is a valid IP6 Address
            // printf("%s IPV6 Address %s\n", ifAddrStruct->ifa_name, addressBuffer6);
            if(ethernet!=NULL)
            {
                if(strcmp(ifAddrStruct->ifa_name, ethernet) == 0)
                {
                    strcpy(addr_ipv6, addressBuffer6);
                }
            }
            else
            {
                strcpy(addr_ipv6, addressBuffer6);
            }
        }
        ifAddrStruct = ifAddrStruct->ifa_next;
    }
    return 0;
}

//************** socket operation start **************
static int connSock(const char *lserv_addr, int lserv_port,int block)
{
    struct sockaddr_in addr;
    int fd = INVALID_SOCKET_FD;
    int ret = 0;

    if(!block)
    {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);    // IPPROTO_TCP
    }
    else
    {
        fd = socket(AF_INET, SOCK_STREAM,0);
    }
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(lserv_addr);
    addr.sin_port = htons(lserv_port);
    ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1)
    {
        if (errno != EINPROGRESS)
        {
            LOG_INFO("connect to socket fd %d failed,errno %d",fd,errno);
            return INVALID_SOCKET_FD;
        }
    }
    return fd;
}

static char *recv_tunnelNoBlockSocket(pTUNNEL_FD ptfd,int *recv_len)
{
    char *data = NULL;
    int dlen = 0;
    char buff[RECV_BUFF_SIZE];
    int ret = 0;
    int fd = INVALID_SOCKET_FD;
    //int recv_cnt = 0;   //recv count

    fd = ptfd->fd;
    if(fd == INVALID_SOCKET_FD)
    {
        return NULL;
    }
    while(1)
    {
        ret = recv(fd,buff,RECV_BUFF_SIZE,0);
        LOG_DEBUG("fd %d recv data result %d,errno %d",fd,ret,errno);
        if(ret == 0)    //socket closed
        {
            //handle socket closed event
            close_tfd(ptfd);
            break;
        }
        else if(ret == -1)
        {
            if(!(EAGAIN == errno || EWOULDBLOCK ==errno || EINTR == errno))   //ECONNREFUSED
            {
                //handle unnormal close socket event
                close_tfd(ptfd);
                break;
            }
            //else if(EAGAIN == errno && recv_cnt++>3)
            else if(EAGAIN == errno)
            {
                LOG_DEBUG("### recv error EAGAIN break");
                break;
                //usleep(100000); //100ms
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
    *recv_len = dlen;
    return data;
}

static int connLocalSrv()
{
    int fd2LServ = INVALID_SOCKET_FD;
    char ipv4[23] = {0};

    //getLocalIP(LOCAL_IFA_NAME, ipv4, NULL);
    getLocalIP(NULL, ipv4, NULL);
    //LOG_INFO("iframe name %s local ipv4:%s",LOCAL_IFA_NAME,ipv4);
    fd2LServ = connSock(ipv4, TUNNEL_LOCAL_SERVICE_PORT,SOCKET_NO_BLOCK);
    return fd2LServ;
}
//************** socket operation end **************

//************** tunnel socket operation start **************
static int init_tfd(pTUNNEL_FD ptfd,TUNNEL_FD_TYPE type,int fd,char *rdata,int rlen,char *wdata,int wlen)
{
    ptfd->fd = fd;
    ptfd->type = type;
    if(rdata !=NULL && rlen > 0)
    {
        ptfd->rdata = malloc(rlen);
        assert(ptfd->rdata!=NULL);
        memcpy(ptfd->rdata,rdata,rlen);
        ptfd->rdlen = rlen;
    }
    else
    {
        ptfd->rdata = NULL;
        ptfd->rdlen = 0;
    }
    if(wdata !=NULL && wlen > 0)
    {
        ptfd->wdata = malloc(wlen);
        assert(ptfd->wdata!=NULL);
        memcpy(ptfd->wdata,wdata,wlen);
        ptfd->wdlen = wlen;
    }
    else
    {
        ptfd->wdata = NULL;
        ptfd->wdlen = 0;
    }
    return 0;
}

static int emptyData_tfd(pTUNNEL_FD ptfd)
{
    if(ptfd == NULL)
    {
        return 0;
    }
    if(ptfd->rdata!=NULL)
    {
        free(ptfd->rdata);
    }
    ptfd->rdata = NULL;
    ptfd->rdlen = 0;
    if(ptfd->wdata!=NULL)
    {
        free(ptfd->wdata);
    }
    ptfd->wdata = NULL;
    ptfd->wdlen = 0;
    return 0;
}

static int close_tfd(pTUNNEL_FD ptfd)
{
    int i;

    //close socket fd
    if(ptfd->fd != INVALID_SOCKET_FD)
    {
        close(ptfd->fd);
        LOG_DEBUG("close socket fd %d,type %s",ptfd->fd,DEBUG_TUNNEL_FD_TYPE_STR[ptfd->type]);
        ptfd->fd = INVALID_SOCKET_FD;
        if(ptfd->rdata != NULL)
        {
            free(ptfd->rdata);
            ptfd->rdata = NULL;
        }
        ptfd->rdlen = 0;
        if(ptfd->wdata != NULL)
        {
            free(ptfd->wdata);
            ptfd->wdata = NULL;
        }
        ptfd->wdlen = 0;
        remove_tfdFromLLst(&gtfd_llst,ptfd);
        if(ptfd->type == TUNNEL_FD_MGNT_TLD)
        {
            LOG_INFO("close tunneld connected socket,exit");
#ifndef BUILD_LIBRARY_TUNNEL
            exit(0);    //exit process will close all socket auto
#endif
        }
        ptfd->type = TUNNEL_FD_TYPE_NOT_SET;
        //check tunnel socket fd pair number
        for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
        {
            if((&(gloTldPair[i].lsrv) == ptfd) && (gloTldPair[i].lsrv2Tld.fd == INVALID_SOCKET_FD))
            {
                gtfdp_num--;
            }
            if((&(gloTldPair[i].lsrv2Tld) == ptfd) && (gloTldPair[i].lsrv.fd == INVALID_SOCKET_FD))
            {
                gtfdp_num--;
            }
        }
    }
    else
    {
        if(ptfd->rdata != NULL)
        {
            free(ptfd->rdata);
            ptfd->rdata = NULL;
        }
        ptfd->rdlen = 0;
        if(ptfd->wdata != NULL)
        {
            free(ptfd->wdata);
            ptfd->wdata = NULL;
        }
        ptfd->wdlen = 0;
        ptfd->type = TUNNEL_FD_TYPE_NOT_SET;
    }
}

//get management type from management socket data
static TUNNEL_MGNT_TYPE getMgntType(char *recv_data,int recv_dlen)
{
    char cmd[TUNNELD_CMD_LENGTH] = {0};

    assert(recv_data!=NULL);
    sscanf(recv_data, "%s", cmd);
    if(strcmp(cmd,TUNNEL_PULL_STR) == 0)
    {
        return TUNNEL_MGNT_TYPE_CHECK_PWD;
    }
    if(strcmp(cmd,TUNNELD_REQUEST_STR) == 0)
    {
        return TUNNEL_MGNT_TYPE_REQUEST;
    }
    return TUNNEL_MGNT_TYPE_NOT_SET;
}
//************** tunnel socket operation end **************

//************** pair of tunnel socket operation start **************
static int getAddPairTfdIndex(TUNNEL_REQRESP_PAIR_TYPE loTldPair[MAX_REQ_RESP_CONN_PAIR])
{
    int index = -1,i;
    for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
    {
        //if(loTldPair[i].lsrv.fd == INVALID_SOCKET_FD && loTldPair[i].lsrv2Tld.fd == INVALID_SOCKET_FD)
        if(loTldPair[i].lsrv2Tld.fd == INVALID_SOCKET_FD)
        {
            index = i;
            break;
        }
    }
    return index;
}
//************** pair of tunnel socket operation end **************


//************** link list function start **************
//add tunnel fd to link list
pTUNNEL_FD_LINK_LIST add_tfd2LLst(pTUNNEL_FD_LINK_LIST llst,pTUNNEL_FD ptfd)
{
    pTUNNEL_FD_LINK_LIST pnew = NULL,pcur = NULL;
    if(ptfd == NULL)
    {
        return llst;
    }
    pnew = malloc(sizeof(TUNNEL_FD_LINK_LIST));
    assert(pnew!=NULL);
    pnew->ptfd = ptfd;
    pnew->next = NULL;
    pcur = llst;
    while(pcur->next!=NULL)
    {
        pcur=pcur->next;
    }
    pcur->next = pnew;
    return llst;
}

//remove tunnel fd from link list
static pTUNNEL_FD_LINK_LIST remove_tfdFromLLst(pTUNNEL_FD_LINK_LIST llst,pTUNNEL_FD ptfd)
{
    pTUNNEL_FD_LINK_LIST pcur,forep;

    pcur = llst->next;  //first link not use
    forep = llst;
    while(pcur!=NULL)
    {
        if(pcur->ptfd == ptfd)
        {
            forep->next = pcur->next;
            free(pcur);
            break;
        }
        forep = pcur;
        pcur=pcur->next;
    }
    return llst;
}

static int empty_llst(pTUNNEL_FD_LINK_LIST llst)
{
    pTUNNEL_FD_LINK_LIST pcur,next;
    pTUNNEL_FD ptfd = NULL;

    pcur = llst->next;  //first link not use
    while(pcur!=NULL)
    {
        next=pcur->next;
        ptfd = pcur->ptfd;
        if(ptfd)
        {
            if(ptfd->fd != INVALID_SOCKET_FD)
            {
                close(ptfd->fd);
                //printf("%s:close socket fd %d,type %s\r\n",__func__,ptfd->fd,DEBUG_TUNNEL_FD_TYPE_STR[ptfd->type]);
                ptfd->fd = INVALID_SOCKET_FD;
            }
            if(ptfd->rdata != NULL)
            {
                free(ptfd->rdata);
                ptfd->rdata = NULL;
            }
            ptfd->rdlen = 0;
            if(ptfd->wdata != NULL)
            {
                free(ptfd->wdata);
                ptfd->wdata = NULL;
            }
            ptfd->wdlen = 0;
            if(ptfd->type == TUNNEL_FD_MGNT_TLD)
            {
                LOG_INFO("close tunneld connected socket,exit");
#ifndef BUILD_LIBRARY_TUNNEL
                exit(0);    //exit process will close all socket auto
#endif
            }
            ptfd->type = TUNNEL_FD_TYPE_NOT_SET;
            ptfd = NULL;
        }
        free(pcur);
        pcur = next;
    }
    llst->next = NULL;
    gtfdp_num = 0;
}

//************** link list function end **************

static int handle_inMgntTld(char *recv_data,int recv_dlen,pTUNNEL_FD ptfd)
{
    TUNNEL_MGNT_TYPE mgntType = TUNNEL_MGNT_TYPE_NOT_SET;
    char cmd[TUNNELD_CMD_LENGTH] = {0};
    char cmd_data[TUNNELD_CMD_DATA_LENGTH]= {0};
    char req_cmd[TUNNELD_CMD_LENGTH] = {0};
    int lsrv_fd,lsrv2tld_fd;
    int index;
    int req_fd = -1;
    char *p_remain = NULL,*p_line=NULL;

    assert(ptfd!=NULL);
    assert(recv_data!=NULL && recv_dlen > 0);

    p_line = strtok_r(recv_data, "\n", &p_remain);
    while(p_line != NULL)
    {
        //mgntType = getMgntType(recv_data,recv_dlen);
        LOG_DEBUG("command line:%s",p_line);
        mgntType = getMgntType(p_line,p_line-recv_data);
        switch(mgntType)
        {
            case TUNNEL_MGNT_TYPE_CHECK_PWD:
                memset(gReqPort,0,sizeof(gReqPort));
                memset(gtoken,0,sizeof(gtoken));
                sscanf(p_line, "%s %s port %s token %s",cmd,cmd_data,gReqPort,gtoken);
                LOG_INFO("received cmd:%s,cmd_data:%s,token:%s,request port:%s",cmd,cmd_data,gtoken,gReqPort);
#ifdef BUILD_LIBRARY_TUNNEL
                if(g_conn_cb)
                {
                    g_conn_cb(atoi(gReqPort));
                }
#endif
                if (strcmp(cmd_data, CONN_TUNNELD_PASSWD_SUCCESS) != 0)
                {
                    LOG_INFO("%s", "fail connect to tunneld,password error,exit");
                    close_tfd(ptfd);
                    free(recv_data);
                    exit(0);
                }
                LOG_INFO("%s", "success connect to tunneld");
                break;
            case TUNNEL_MGNT_TYPE_REQUEST:
            {
                if(gtfdp_num >= MAX_REQ_RESP_CONN_PAIR - 1)
                {
                    LOG_INFO("%s","max connection");
                    break;
                }
                index = getAddPairTfdIndex(gloTldPair);
                if(index == -1)
                {
                    LOG_INFO("get index failed.");
                    //return 0;
                    break;
                }
                //connect tunneld
                lsrv2tld_fd = connSock(TUNNELD_ADDR,TUNNELD_PORT,SOCKET_NO_BLOCK);
                //DBUG_PEER_SOCK_INFO(lsrv2tld_fd);
                //DBUG_SOCK_INFO(lsrv2tld_fd);
                if(lsrv2tld_fd == INVALID_SOCKET_FD)
                {
                    LOG_INFO("%s","connect local service failed.");
                    //return 0;
                    break;
                }
                LOG_DEBUG("%s",p_line);
                sscanf(p_line, "%s %d",cmd,&req_fd);
                LOG_DEBUG("received cmd:%s,request socket fd:%d",cmd,req_fd);
                sprintf(req_cmd,"%s %s %d",TUNNEL_PULL_STR,gtoken,req_fd); /*pull cmd with token and request socket fd*/
                init_tfd(&gloTldPair[index].lsrv2Tld,TUNNEL_FD_LSRV2TLD,lsrv2tld_fd,NULL,0,req_cmd,strlen(req_cmd)+1);
                add_tfd2LLst(&gtfd_llst,&gloTldPair[index].lsrv2Tld);
                //local service
                if(gloTldPair[index].lsrv.fd == INVALID_SOCKET_FD)
                {
                    lsrv_fd = connLocalSrv(); //connect local service
                    if(lsrv_fd == INVALID_SOCKET_FD)
                    {
                        LOG_INFO("%s","connect local service failed.");
                        //return 0;
                        break;
                    }
                    init_tfd(&gloTldPair[index].lsrv,TUNNEL_FD_LSRV,lsrv_fd,NULL,0,NULL,0);
                    add_tfd2LLst(&gtfd_llst,&gloTldPair[index].lsrv);
                    gtfdp_num++;
                }
                else
                {
                    emptyData_tfd(&gloTldPair[index].lsrv);
                }
                LOG_DEBUG("exist %d pairs local sevice fd and local to tunneld fd",gtfdp_num);
            }
            break;
            default:
                break;
        }
        p_line = strtok_r(NULL, "\n", &p_remain);
    }
    return 0;
}

static int handle_inLSrv(char *recv_data,int recv_dlen,pTUNNEL_FD ptfd)
{
    int i;
    char *p_write_date = NULL;
    int *p_write_dlen = NULL;
    pTUNNEL_FD plsrv2Tld = NULL;

    if(recv_data!=NULL && recv_dlen > 0)
    {
        for(i=0; i<gtfdp_num; i++)
        {
            if(&(gloTldPair[i].lsrv) == ptfd)
            {
                LOG_DEBUG("pair index %d",i);
                plsrv2Tld = &gloTldPair[i].lsrv2Tld;
                break;
            }
        }
        if(plsrv2Tld != NULL && plsrv2Tld->fd != INVALID_SOCKET_FD)
        {
            LOG_DEBUG("plsrv2Tld->wdata:%p,plsrv2Tld->wdlen:%d",plsrv2Tld->wdata,plsrv2Tld->wdlen);
            append_data(&(plsrv2Tld->wdata),&(plsrv2Tld->wdlen),recv_data,recv_dlen);
            LOG_DEBUG("plsrv2Tld->wdata:%p,plsrv2Tld->wdlen:%d",plsrv2Tld->wdata,plsrv2Tld->wdlen);
        }
    }
    return 0;
}

static int handle_inLSrv2Tld(char *recv_data,int recv_dlen,pTUNNEL_FD ptfd)
{
    int i;
    char *p_write_date = NULL;
    int *p_write_dlen = NULL;
    pTUNNEL_FD plsrv = NULL;
    int lsrv_fd = INVALID_SOCKET_FD;

    if(recv_data!=NULL && recv_dlen > 0)
    {
        for(i=0; i<gtfdp_num; i++)
        {
            if(&(gloTldPair[i].lsrv2Tld) == ptfd)
            {
                LOG_DEBUG("pair index %d",i);
                plsrv = &gloTldPair[i].lsrv;
                break;
            }
        }
        if(plsrv->fd != INVALID_SOCKET_FD)
        {
            LOG_DEBUG("plsrv2Tld->wdata:%p,plsrv2Tld->wdlen:%d",plsrv->wdata,plsrv->wdlen);
            append_data(&(plsrv->wdata),&(plsrv->wdlen),recv_data,recv_dlen);
            LOG_DEBUG("plsrv2Tld->wdata:%p,plsrv2Tld->wdlen:%d",plsrv->wdata,plsrv->wdlen);
        }
        else     //connect to local service
        {
            lsrv_fd = connLocalSrv();
            if(lsrv_fd != INVALID_SOCKET_FD)
            {
                init_tfd(plsrv,TUNNEL_FD_LSRV,lsrv_fd,NULL,0,recv_data,recv_dlen);
                add_tfd2LLst(&gtfd_llst,plsrv);
            }
        }
    }
    return 0;
}

static int handle_fdReadEvnt(TUNNEL_FD_TYPE type,pTUNNEL_FD ptfd)
{
    char *recv_data = NULL;
    int recv_dlen = 0;

    // receive data
    recv_data = recv_tunnelNoBlockSocket(ptfd,&recv_dlen);
    if(recv_data == NULL)
    {
        // LOG_DEBUG("no data received from socket fd %d",fd);
        return 0 ;
    }
    LOG_DEBUG("fd %d,type(%d) %s,received %d bytes",ptfd->fd,type,DEBUG_TUNNEL_FD_TYPE_STR[type],recv_dlen);
    //LOG_DEBUG("%s",recv_data);
    switch (type)
    {
        case TUNNEL_FD_MGNT_TLD:
            //PRINT_RECV_DATA(recv_data,recv_dlen,1);
            handle_inMgntTld(recv_data,recv_dlen,ptfd);
            break;
        case TUNNEL_FD_LSRV:
        {
            //handle data that received from local service socket fd
            //PRINT_RECV_DATA(recv_data,recv_dlen,0);
            handle_inLSrv(recv_data,recv_dlen,ptfd);
        }
        break;
        case TUNNEL_FD_LSRV2TLD:
        {
            //handle with data that received from local service to tunneld socket fd
            //PRINT_RECV_DATA(recv_data,recv_dlen,1);
            handle_inLSrv2Tld(recv_data,recv_dlen,ptfd);
        }
        break;
        default:
            break;
    }
    if(recv_data != NULL)
    {
        free(recv_data);
        recv_data = NULL;
        recv_dlen = 0;
    }
    return 0;
}

static int handle_fdWriteEvnt(TUNNEL_FD_TYPE type,pTUNNEL_FD ptfd)
{
    char *data = NULL;
    int dlen = 0;
    int fd = INVALID_SOCKET_FD;
    int ret = 0;

    assert(ptfd!=NULL);
    fd = ptfd->fd;
    data = ptfd->wdata;
    dlen = ptfd->wdlen;
    if(!(fd != INVALID_SOCKET_FD && data != NULL && dlen > 0))
    {
        // LOG_DEBUG("no data write to socket fd %d,data:%p,dlen:%d",fd,data,dlen);
        return 0;
    }
    ret = send(fd, data,dlen, 0);
    if(ret == -1)
    {
        LOG_DEBUG("send %d bytes data to socket fd %d failed",dlen,fd);
        return 0;
    }
    else if(ret < dlen && ret > 0)
    {
        char *tmp = NULL;

        LOG_DEBUG("send part of %d bytes data to socket fd %d,remain %d",dlen,fd,dlen-ret);
        tmp = malloc(dlen - ret);
        assert(tmp!=NULL);
        memcpy(tmp,data+ret,dlen-ret);
        ptfd->wdata = tmp;
        ptfd->wdlen = dlen-ret;
    }
    else if(ret == dlen)
    {
        LOG_DEBUG("send %d bytes data to socket fd %d,type %s",dlen,fd,DEBUG_TUNNEL_FD_TYPE_STR[type]);
        //LOG_DEBUG("send %d bytes data to socket fd %d,\ndata:%s",dlen,fd,data);
        //PRINT_RECV_DATA(data,dlen);
        ptfd->wdata = NULL;
        ptfd->wdlen = 0;
    }
    free(data);
    return 0;
}

static int handle_fdExptEvnt(TUNNEL_FD_TYPE type,pTUNNEL_FD ptfd)
{
    assert(ptfd!=NULL);
    //TODO:deal exception
    switch (type)
    {
        case TUNNEL_FD_LSRV:

            break;
        case TUNNEL_FD_LSRV2TLD:

            break;
        case TUNNEL_FD_TYPE_COUNT:

            break;
        default:
            break;
    }
    return 0;
}

static int fdSetTunnel(pTUNNEL_FD tfd,fd_set *prs,fd_set *pws,fd_set *pes,fd_set **recordws)
{
    if (tfd->fd == INVALID_SOCKET_FD)
    {
        return 0;
    }
    FD_SET(tfd->fd, prs);
    FD_SET(tfd->fd, pes);
    if(tfd->wdata != NULL && tfd->wdlen > 0)
    {
        FD_SET(tfd->fd, pws);
        *recordws=pws;
    }
    return 0;
}

#ifndef BUILD_LIBRARY_TUNNEL
static int load_iniConfig()
{
    dictionary *ini;
    const char *p_srv_addr=NULL;
    const char *p_srv_port=NULL;
    const char *p_srv_authStr=NULL;
    const char *p_local_srv_port=NULL;

    ini = iniparser_load(TUNNEL_CONFIG_FILE);
    p_srv_addr = iniparser_getstring(ini, "config:server_addr", DEFAULT_SERVER_ADDR);
    p_srv_port=iniparser_getstring(ini, "config:server_port",DEFAULT_SERVER_PORT);
    p_srv_authStr = iniparser_getstring(ini, "config:auth_str",DEFAULT_SERVER_AUTH_STR);
    p_local_srv_port = iniparser_getstring(ini, "config:local_srv_port",DEFAULT_LOCAL_SERVER_PORT);
    sprintf(TUNNELD_ADDR,"%s",p_srv_addr);
    TUNNELD_PORT = atoi(p_srv_port);
    TUNNEL_LOCAL_SERVICE_PORT = atoi(p_local_srv_port);
    sprintf(TUNNELD_AUTH_STR,"%s",p_srv_authStr);
    iniparser_freedict(ini);
    return 0;
}
#endif

#ifdef BUILD_LIBRARY_TUNNEL
void set_connTunnel_cb(CONN_TUNNEL_CALLBACK conn_fun)
{
    g_conn_cb = conn_fun;
}

void set_closeTunnel_cb(CLOSE_TUNNEL_CALLBACK cb)
{
    g_close_cb = cb;
}

void close_tunnel_ex()
{
    gRunTunnel = 0;
}
#endif

static time_t gen_heartBeat(time_t preTm,pTUNNEL_FD mgnTfd)
{
    time_t cur_tm=0;
    
    time(&cur_tm);
    if((cur_tm-preTm)>=HEART_BEAT_INTERVAL)
    {
        char beatStr[64]={0};
        int beatLen=0;
        sprintf(beatStr,"%s %s %ld",gtoken,HEART_BEAT_STR,cur_tm);
        beatLen = strlen(beatStr)+1;
        mgnTfd->wdata=malloc(beatLen);
        if(mgnTfd->wdata!=NULL)
        {
            memcpy(mgnTfd->wdata,beatStr,beatLen);
            mgnTfd->wdlen = beatLen;
        }
        return cur_tm;
    }
    return preTm;
}

#ifdef BUILD_LIBRARY_TUNNEL
int create_tunnel_ex(char *ip, int r_port, int l_port, char *password)
#else
int main(int argc, int *args)
#endif
{
    struct timeval tv;
    fd_set rs, ws, es;
    fd_set *pws = NULL; //pointer of write fd set
    int fd,i,cnt,max_fd;
    TUNNEL_FD tfd_mgt;
    char authStr[128]= {0};
    time_t preBeat_tm = 0;
#ifdef BUILD_LIBRARY_TUNNEL

    sprintf(TUNNELD_ADDR,"%s",ip);
    TUNNELD_PORT = r_port;
    TUNNEL_LOCAL_SERVICE_PORT = l_port;
    sprintf(TUNNELD_AUTH_STR,"%s",password);
    sprintf(TUNNELD_ADDR,"%s",ip);
    printf("tunneld server addr:%s,port:%d,local service port:%d,auth string:%s\r\n",TUNNELD_ADDR,
           TUNNEL_LOCAL_SERVICE_PORT,TUNNELD_PORT,TUNNELD_AUTH_STR);
#else
    load_iniConfig();
#endif
    LOG_INFO("tunneld server addr:%s,port:%d,local service port:%d,auth string:%s",TUNNELD_ADDR,
             TUNNEL_LOCAL_SERVICE_PORT,TUNNELD_PORT,TUNNELD_AUTH_STR);
    fd = connSock(TUNNELD_ADDR,TUNNELD_PORT,SOCKET_NO_BLOCK);
    if(fd == INVALID_SOCKET_FD)
    {
        LOG_INFO("%s", "connect to tunneld server failed");
        return 0;
    }
    //set password to tunneld management socket fd
    sprintf(authStr,"%s %s",TUNNEL_PASSWD_CMD,TUNNELD_AUTH_STR);
    init_tfd(&tfd_mgt,TUNNEL_FD_MGNT_TLD,fd,NULL,0,authStr,strlen(authStr) + 1/* add '\0'*/);
    //new feature
    gtfd_llst.ptfd = NULL;  //do not user first link
    gtfd_llst.next = NULL;
    add_tfd2LLst(&gtfd_llst,&tfd_mgt);
    for(i=0; i<MAX_REQ_RESP_CONN_PAIR; i++)
    {
        init_tfd(&gloTldPair[i].lsrv,TUNNEL_FD_TYPE_NOT_SET,INVALID_SOCKET_FD,NULL,0,NULL,0);
        init_tfd(&gloTldPair[i].lsrv2Tld,TUNNEL_FD_TYPE_NOT_SET,INVALID_SOCKET_FD,NULL,0,NULL,0);
    }
    time(&preBeat_tm);
    gRunTunnel = 1;
    while(gRunTunnel)
    {
        pTUNNEL_FD ptfd = NULL;
        pTUNNEL_FD_LINK_LIST ptfd_llst;

        // each time empty fd set
        FD_ZERO(&rs);
        FD_ZERO(&ws);
        FD_ZERO(&es);
        pws = NULL;
        //add local service tunnel fd and connected service tunneld to tunnel link list
        //LOG_DEBUG("exist %d pairs local sevice fd and local to tunneld fd",gtfdp_num);
        max_fd = 0;
        //add tunnel link list fd to read/write/exception set
        ptfd_llst = gtfd_llst.next;    //first link not use
        while(ptfd_llst != NULL)
        {
            ptfd = ptfd_llst->ptfd;
            fdSetTunnel(ptfd,&rs,&ws,&es,&pws);
            //LOG_DEBUG("select fd %d,type:%s",ptfd->fd,DEBUG_TUNNEL_FD_TYPE_STR[ptfd->type]);
            //printf("select fd %d,type:%s\r\n",ptfd->fd,DEBUG_TUNNEL_FD_TYPE_STR[ptfd->type]);
            if(max_fd < ptfd->fd)
            {
                max_fd = ptfd->fd;
            }
            ptfd_llst = ptfd_llst->next;
        }
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        cnt = select(max_fd + 1, &rs, pws, &es, &tv);
        //LOG_DEBUG("select count %d,gtfdp_num %d",cnt,gtfdp_num);
        if (cnt <= 0)
        {
            preBeat_tm = gen_heartBeat(preBeat_tm,&tfd_mgt);
            continue;
        }
        // LOG_DEBUG("select count %d", cnt);
        ptfd_llst = gtfd_llst.next;    //first link not use
        while(ptfd_llst != NULL)
        {
            ptfd = ptfd_llst->ptfd;
            if (FD_ISSET(ptfd->fd, &rs))
            {
                handle_fdReadEvnt(ptfd->type,ptfd);
            }
            if (FD_ISSET(ptfd->fd, &ws))
            {
                handle_fdWriteEvnt(ptfd->type,ptfd);
            }
            if (FD_ISSET(ptfd->fd, &es))
            {
                handle_fdExptEvnt(ptfd->type,ptfd);
            }
            ptfd_llst = ptfd_llst->next;
        }
        //sleep(2);   //debug sleep
    }
    empty_llst(&gtfd_llst); //close all socket fd and empty link list
#ifdef BUILD_LIBRARY_TUNNEL
    if(g_close_cb)
    {
        g_close_cb();
    }
#endif
}
