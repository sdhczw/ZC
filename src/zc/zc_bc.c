/**
******************************************************************************
* @file     zc_bc.c
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    broadcast
******************************************************************************
*/
#include <zc_bc.h>
#include <zc_protocol_controller.h>

int g_Bcfd = 0;
u8* g_pu8RemoteAddr = NULL;
u8* g_pu8ClientAddr = NULL;

unsigned int g_u32GloablIp;
extern u32 g_u32BcSleepCount;
extern ZC_LanConfigInfo g_struLanInfo;
/*************************************************
* Function: ZC_SendBc
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_SendBc()
{
    u16 u16Len;
    static int sleepcount = 0;
    ZC_SendParam struParam;

    if (PCT_STATE_CONNECT_CLOUD != g_struProtocolController.u8MainState)
    {
        sleepcount = 0;
        return;
    }

    if (ZC_MAGIC_FLAG == g_struZcConfigDb.struDeviceInfo.u32UnBcFlag)
    {
        sleepcount = 0;
        return;
    }        
    sleepcount++;
    if (sleepcount > g_u32BcSleepCount)
    {
        
        EVENT_BuildBcMsg(g_u8MsgBuildBuffer, &u16Len);

        if (g_struProtocolController.u16SendBcNum < (PCT_SEND_BC_MAX_NUM))
        {
            struParam.u8NeedPoll = 0;
            struParam.pu8AddrPara = g_pu8RemoteAddr;
            g_struProtocolController.pstruMoudleFun->pfunSendUdpData(g_Bcfd, g_u8MsgBuildBuffer, u16Len, &struParam);  
            g_struProtocolController.u16SendBcNum++;
        }
        sleepcount = 0;
    }
    
}
/*************************************************
* Function: ZC_SendClientQueryReq
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_SendClientQueryReq(u8 *pu8Msg, u16 u16RecvLen)
{
    ZC_MessageHead *pstruMsg;
    ZC_ClientQueryRsp * pstruRsp= (ZC_ClientQueryRsp *)g_u8MsgBuildBuffer;
    u16 u16Len;
    u8 *pu8DeviceId;
    u8 *pu8Domain;    
    u32 u32Index;
    ZC_ClientQueryReq *pstruQuery;
    ZC_SendParam struParam;
    u8 u8DeivceIdLen = 0;
#if 0    
    if (g_struProtocolController.u8MainState < PCT_STATE_ACCESS_NET)
    {
        return;
    }
#endif
    if (u16RecvLen != sizeof(ZC_MessageHead) + sizeof(ZC_ClientQueryReq))
    {
        return;
    }
    
    pstruMsg = (ZC_MessageHead *)pu8Msg;
    pstruQuery = (ZC_ClientQueryReq *)(pstruMsg + 1);

    if (ZC_CODE_CLIENT_QUERY_REQ != pstruMsg->MsgCode)
    {
        return;
    }
    ZC_GetStoreInfor(ZC_GET_TYPE_DEVICEID, &pu8DeviceId);
    ZC_GetStoreInfor(ZC_GET_TYPE_DOMAIN, &pu8Domain);
    u8DeivceIdLen = strlen((const char *)pu8DeviceId);

    /*Only first 6 bytes is vaild*/
    for (u32Index = 0; u32Index < 6; u32Index++)
    {
        if (pstruQuery->u8Domain[u32Index] != pu8Domain[u32Index])
        {
            return;
        }
        
    }
    
    pstruRsp->addr[3] = g_u32GloablIp & 0xff;
    pstruRsp->addr[2] = (g_u32GloablIp >> 8) & 0xff;
    pstruRsp->addr[1] = (g_u32GloablIp >> 16) & 0xff;
    pstruRsp->addr[0] = (g_u32GloablIp >> 24)  & 0xff;
    memcpy(pstruRsp->u8Domain, pu8Domain, ZC_DOMAIN_LEN);
    memcpy(pstruRsp->DeviceId, pu8DeviceId, u8DeivceIdLen);
    EVENT_BuildMsg(ZC_CODE_CLIENT_QUERY_RSP, 0, g_u8MsgBuildBuffer, &u16Len, (u8*)pstruRsp, sizeof(ZC_ClientQueryRsp)+u8DeivceIdLen);
    struParam.u8NeedPoll = 0;
    struParam.pu8AddrPara = g_pu8RemoteAddr;
    g_struProtocolController.pstruMoudleFun->pfunSendUdpData(g_Bcfd, g_u8MsgBuildBuffer, u16Len, &struParam);  
}

/*************************************************
* Function: ZC_HandleLanMsg
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_HandleLanMsg(u8* pu8RemoteAddr,u8 *pu8Data, u32 u32DataLen)
{
    u8 *pu8Key;
    u8 u8Iv[ZC_HS_SESSION_KEY_LEN];
    u32 u32CiperLen;
    ZC_MessageHead *pstruMsgHead;
    ZC_SecHead *pstruSecHead;
    pstruSecHead = (ZC_SecHead *)pu8Data;

    if (ZC_HTONS(pstruSecHead->u16TotalMsg) >= 1052)
    {
        return;
    }

    g_pu8ClientAddr = pu8RemoteAddr;

    pu8Key = g_struLanInfo.u8TokenKey;

    memcpy(u8Iv, pu8Key, ZC_HS_SESSION_KEY_LEN);

    AES_CBC_Decrypt(pu8Data + sizeof(ZC_SecHead), ZC_HTONS(pstruSecHead->u16TotalMsg), 
        pu8Key, ZC_HS_SESSION_KEY_LEN, 
        u8Iv, ZC_HS_SESSION_KEY_LEN, 
        g_u8MsgBuildBuffer, &u32CiperLen);

    pstruMsgHead = (ZC_MessageHead *)g_u8MsgBuildBuffer;
    if (ZC_HTONS(pstruMsgHead->Payloadlen) >= 1044)
    {
        ZC_Printf("Payloadlen > 1044\n");
        return;
    }
    if(ZC_RET_ERROR == PCT_CheckCrc(pstruMsgHead->TotalMsgCrc,(u8 *)(pstruMsgHead + 1),ZC_HTONS(pstruMsgHead->Payloadlen)))
    {
        ZC_Printf("Crc error\n");
        return; 
    }

    ZC_Printf("Msgcode is %d\n", pstruMsgHead->MsgCode);
    switch (pstruMsgHead->MsgCode)
    {
        case ZC_CODE_LAN_SET_LICENSE:
            ZC_LanSetLicense((u8 *)(pstruMsgHead + 1), ZC_HTONS(pstruMsgHead->Payloadlen));
            break;
        default:
            break;
    }
}

/******************************* FILE END ***********************************/


