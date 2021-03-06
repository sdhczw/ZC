/**
******************************************************************************
* @file     zc_configuration.c
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    configuration
******************************************************************************
*/
#include <zc_configuration.h>
#include <zc_protocol_controller.h>

ZC_ConfigDB g_struZcConfigDb;
ZC_RegisterInfo g_struRegisterInfo;
ZC_LicenseInfo g_struLiceInfo;
ZC_LanConfigInfo g_struLanInfo;

extern u8* g_pu8ClientAddr;

u8 g_u8DefaultCloudKey[ZC_CLOUD_KEY_MAX_LEN] = 
{
    0xb8, 0xd9, 0x35, 0xe4,
    0xd6, 0xd8, 0xf2, 0xd6,
    0xc8, 0x28, 0x2f, 0x9f,
    0xd9, 0x62, 0x48, 0xc7,
    0x96, 0xa9, 0xed, 0x5b,
    0x5a, 0x1a, 0x95, 0x59,
    0xd2, 0x3c, 0xbb, 0x5f,
    0x1b, 0x03, 0x07, 0x3f,
    0x01, 0x00, 0x01, 0x00
};
u8 g_u8DefaultTokenKey[ZC_HS_SESSION_KEY_LEN] = 
{
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05
};

/*************************************************
* Function: ZC_ConfigInitPara
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_ConfigInitPara()
{
    u32 u32Crc;
    g_struProtocolController.pstruMoudleFun->pfunReadFlash((u8 *)&g_struZcConfigDb,sizeof(g_struZcConfigDb));
    u32Crc = crc16_ccitt(((u8 *)&g_struZcConfigDb) + 4, sizeof(g_struZcConfigDb) - 4);
    if(u32Crc != g_struZcConfigDb.u32Crc)
    {
        g_struZcConfigDb.struSwitchInfo.u32SecSwitch = 1;
        g_struZcConfigDb.struSwitchInfo.u32TraceSwitch = 0;
        g_struZcConfigDb.struSwitchInfo.u32WifiConfig = 0;
        g_struZcConfigDb.struSwitchInfo.u32ServerAddrConfig = 0;
        g_struZcConfigDb.struSwitchInfo.u16ServerPort = ZC_CLOUD_PORT;

        memcpy(g_struZcConfigDb.struCloudInfo.u8CloudAddr, ZC_CLOUD_SERVER, ZC_CLOUD_ADDR_MAX_LEN);
        memcpy(g_struZcConfigDb.struCloudInfo.u8CloudKey, g_u8DefaultCloudKey, ZC_CLOUD_KEY_MAX_LEN);
        memcpy(g_struZcConfigDb.struCloudInfo.u8TokenKey, g_u8DefaultTokenKey, ZC_HS_SESSION_KEY_LEN);

        g_struZcConfigDb.struConnection.u32MagicFlag = 0xFFFFFFFF;
        g_struZcConfigDb.struDeviceInfo.u32UnBindFlag = 0xFFFFFFFF;
        g_struZcConfigDb.struDeviceInfo.u32UnBcFlag = 0xFFFFFFFF;
        ZC_Printf("no para, use default\n");
    }

    g_struProtocolController.pstruMoudleFun->pfunReadLicense((u8 *)&g_struLiceInfo,sizeof(u32));

    if (ZC_MAGIC_FLAG != g_struLiceInfo.u32MagicFlag)
    {
        ZC_Printf("No license\n");
        g_struLiceInfo.u8Status = ZC_AUTH_NONE;
        return;
    }
    
    g_struProtocolController.pstruMoudleFun->pfunReadLicense((u8 *)&g_struLiceInfo,sizeof(g_struLiceInfo));
    u32Crc = crc16_ccitt(((u8 *)&g_struLiceInfo) + 8, ZC_LICENSE_LEN);
    if(u32Crc != g_struLiceInfo.u32Crc)
    {   
        ZC_Printf("ZC_ConfigInitPara:Crc is not same\n");
        g_struLiceInfo.u8Status = ZC_AUTH_ERROR;
    }
    else
    {
        ZC_Printf("License is ok\n");
        g_struLiceInfo.u8Status = ZC_AUTH_OK;
    }
}

/*************************************************
* Function: ZC_ConfigPara
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_ConfigPara(u8 *pu8Data)
{
    ZC_Configuration *pstruConfig;
    pstruConfig = (ZC_Configuration*)pu8Data;

    g_struZcConfigDb.struSwitchInfo.u32SecSwitch = ZC_HTONL(pstruConfig->u32SecSwitch);
    g_struZcConfigDb.struSwitchInfo.u32TraceSwitch = ZC_HTONL(pstruConfig->u32TraceSwitch);
    g_struZcConfigDb.struSwitchInfo.u32WifiConfig = ZC_HTONL(pstruConfig->u32WifiConfig);
    g_struZcConfigDb.struSwitchInfo.u32ServerAddrConfig = ZC_HTONL(pstruConfig->u32ServerAddrConfig);

    g_struZcConfigDb.struSwitchInfo.u32ServerIp = ZC_HTONL(pstruConfig->u32IpAddr);
    g_struZcConfigDb.struSwitchInfo.u16ServerPort = ZC_CLOUD_PORT;

    memcpy(g_struZcConfigDb.struSwitchInfo.u8Password, pstruConfig->u8Password, ZC_PASSWORD_MAX_LEN);
    memcpy(g_struZcConfigDb.struSwitchInfo.u8Ssid, pstruConfig->u8Ssid, ZC_SSID_MAX_LEN);
    
    memcpy(g_struZcConfigDb.struCloudInfo.u8CloudAddr, pstruConfig->u8CloudAddr, ZC_CLOUD_ADDR_MAX_LEN);
    memcpy(g_struZcConfigDb.struCloudInfo.u8CloudKey, pstruConfig->u8CloudKey, ZC_CLOUD_KEY_MAX_LEN);
    g_struZcConfigDb.u32Crc = crc16_ccitt(((u8 *)&g_struZcConfigDb) + 4, sizeof(g_struZcConfigDb) - 4);
    g_struProtocolController.pstruMoudleFun->pfunWriteFlash((u8*)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
}

/*************************************************
* Function: ZC_StoreRegisterInfo
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_StoreRegisterInfo(u8 *pu8Data,u16 u16DataLen,u8 u8RegisterFlag)
{
    ZC_RegisterReq *pstruRegisterMsg;
    u8 u8Mac[ZC_SERVER_MAC_LEN];
    PTC_ProtocolCon *pstruCon; pstruCon = &g_struProtocolController;
    u16 u16DeviceIdLen = u16DataLen - ZC_EQVERSION_LEN - ZC_MODULE_KEY_LEN - ZC_DOMAIN_LEN;
    pstruRegisterMsg = (ZC_RegisterReq *)pu8Data;

    memset(g_struRegisterInfo.u8DeviceId,0,ZC_HS_DEVICE_ID_LEN+ZC_DOMAIN_LEN);
    memcpy(g_struRegisterInfo.u8PrivateKey, pstruRegisterMsg->u8ModuleKey, ZC_MODULE_KEY_LEN);
    memcpy(pstruCon->u8SessionKey, pstruRegisterMsg->u8ModuleKey, ZC_HS_SESSION_KEY_LEN);
    memcpy(pstruCon->IvSend, pstruRegisterMsg->u8ModuleKey, ZC_HS_SESSION_KEY_LEN);
    memcpy(pstruCon->IvRecv, pstruRegisterMsg->u8ModuleKey, ZC_HS_SESSION_KEY_LEN);
    if((u8RegisterFlag)||(0 == u16DeviceIdLen))
	{
        memset(g_struRegisterInfo.u8DeviceId, '0', ZC_HS_OLDDEVICE_ID_LEN);
		g_struProtocolController.pstruMoudleFun->pfunGetMac(u8Mac);
		memcpy(g_struRegisterInfo.u8DeviceId + (ZC_HS_OLDDEVICE_ID_LEN - ZC_SERVER_MAC_LEN), u8Mac, ZC_SERVER_MAC_LEN);
	}
	else
	{
		memcpy(g_struRegisterInfo.u8DeviceId, pstruRegisterMsg->u8DeviceId, u16DeviceIdLen);
	}
    memcpy(g_struRegisterInfo.u8DeviceId + ZC_HS_DEVICE_ID_LEN, pstruRegisterMsg->u8Domain, ZC_DOMAIN_LEN);
    memcpy(g_struRegisterInfo.u8EqVersion, pstruRegisterMsg->u8EqVersion, ZC_EQVERSION_LEN);

    if (PCT_LOCAL_STATIC_TOKEN == g_struProtocolController.u32LocalTokenFlag)
    {
        PCT_SetAesKey(g_struZcConfigDb.struCloudInfo.u8TokenKey);
    }
    PCT_SetAesKey(g_struLanInfo.u8TokenKey);

    memcpy(g_struLanInfo.IvRecv, g_struLanInfo.u8TokenKey, ZC_HS_SESSION_KEY_LEN);
    memcpy(g_struLanInfo.IvSend, g_struLanInfo.u8TokenKey, ZC_HS_SESSION_KEY_LEN);
    
}


/*************************************************
* Function: ZC_StoreTokenKey
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_StoreTokenKey(u8 *pu8Data)
{
    g_struZcConfigDb.struDeviceInfo.u32UnBcFlag = ZC_MAGIC_FLAG;   
    memcpy(g_struZcConfigDb.struCloudInfo.u8TokenKey, pu8Data, ZC_HS_SESSION_KEY_LEN);
    g_struZcConfigDb.u32Crc = crc16_ccitt(((u8 *)&g_struZcConfigDb) + 4, sizeof(g_struZcConfigDb) - 4);
    g_struProtocolController.pstruMoudleFun->pfunWriteFlash((u8*)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
}

/*************************************************
* Function: ZC_StoreConnectionInfo
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_StoreConnectionInfo(u8 *pu8Ssid, u8 *pu8Password)
{
    g_struZcConfigDb.struConnection.u32MagicFlag = ZC_MAGIC_FLAG;
    memcpy(g_struZcConfigDb.struConnection.u8Ssid, pu8Ssid, ZC_SSID_MAX_LEN);
    memcpy(g_struZcConfigDb.struConnection.u8Password, pu8Password, ZC_PASSWORD_MAX_LEN);
    g_struZcConfigDb.u32Crc = crc16_ccitt(((u8 *)&g_struZcConfigDb) + 4, sizeof(g_struZcConfigDb) - 4);
    g_struProtocolController.pstruMoudleFun->pfunWriteFlash((u8*)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
}

/*************************************************
* Function: ZC_StoreConnectionInfo
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_StoreAccessInfo(u8 *pu8ServerIp, u8 *pu8ServerPort)
{
    g_struZcConfigDb.struConnection.u32MagicFlag = ZC_MAGIC_FLAG;
    g_struZcConfigDb.struSwitchInfo.u32ServerAddrConfig = 1;
    memcpy(&g_struZcConfigDb.struSwitchInfo.u32ServerIp, pu8ServerIp, ZC_SERVER_ADDR_MAX_LEN);
    memcpy(&g_struZcConfigDb.struSwitchInfo.u16ServerPort, pu8ServerPort, ZC_SERVER_PORT_MAX_LEN);
    g_struZcConfigDb.u32Crc = crc16_ccitt(((u8 *)&g_struZcConfigDb) + 4, sizeof(g_struZcConfigDb) - 4);
    g_struProtocolController.pstruMoudleFun->pfunWriteFlash((u8*)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
}

/*************************************************
* Function: ZC_GetStoreInfor
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_GetStoreInfor(u8 u8Type, u8 **pu8Data)
{
    switch(u8Type)
    {
        case ZC_GET_TYPE_CLOUDKEY:
            *pu8Data = g_struZcConfigDb.struCloudInfo.u8CloudKey;
            break;
        case ZC_GET_TYPE_DEVICEID:
            *pu8Data = g_struRegisterInfo.u8DeviceId;
            break;
        case ZC_GET_TYPE_DOMAIN:
            *pu8Data = g_struRegisterInfo.u8Domain;
            break;
        case ZC_GET_TYPE_PRIVATEKEY:
            *pu8Data = g_struRegisterInfo.u8PrivateKey;
            break;
        case ZC_GET_TYPE_VESION:
            *pu8Data = g_struRegisterInfo.u8EqVersion;
            break;
        case ZC_GET_TYPE_TOKENKEY:
            *pu8Data = g_struZcConfigDb.struCloudInfo.u8TokenKey;
            break;
    }
}

/*************************************************
* Function: ZC_ConfigPara
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_ConfigUnBind(u32 u32UnBindFlag)
{
    g_struZcConfigDb.struDeviceInfo.u32UnBindFlag = u32UnBindFlag; 
    g_struZcConfigDb.u32Crc = crc16_ccitt(((u8 *)&g_struZcConfigDb) + 4, sizeof(g_struZcConfigDb) - 4);    
    g_struProtocolController.pstruMoudleFun->pfunWriteFlash((u8*)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
}

/*************************************************
* Function: ZC_ConfigReset
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void ZC_ConfigReset()
{
    g_struZcConfigDb.struSwitchInfo.u32ServerAddrConfig = 0;            
    g_struZcConfigDb.struDeviceInfo.u32UnBcFlag = 0xFFFFFFFF;
    g_struZcConfigDb.u32Crc = crc16_ccitt(((u8 *)&g_struZcConfigDb) + 4, sizeof(g_struZcConfigDb) - 4);    
    g_struProtocolController.pstruMoudleFun->pfunWriteFlash((u8 *)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
    g_struProtocolController.pstruMoudleFun->pfunRest();
}

/*************************************************
* Function: ZC_ConfigResetAccess
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void ZC_ConfigResetAccess()
{
    g_struZcConfigDb.struSwitchInfo.u32ServerAddrConfig = 0;
    g_struZcConfigDb.u32Crc = crc16_ccitt(((u8 *)&g_struZcConfigDb) + 4, sizeof(g_struZcConfigDb) - 4);    
    g_struProtocolController.pstruMoudleFun->pfunWriteFlash((u8 *)&g_struZcConfigDb, sizeof(ZC_ConfigDB));
}
/*************************************************
* Function: ZC_SendMsgToClient
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u32 ZC_SendMsgToClient(ZC_SecHead *pstruSecHead, u8 *pu8PlainData)
{
    u32 u32RetVal;
    u16 u16Len;
    u16 u16PaddingLen;
    ZC_SendParam struParam;
    u8 *pu8Buf = NULL;
    u32 u32OutLen = 0;
    u8 *u8SessionKey = g_struLanInfo.u8TokenKey;
    u8 IvSend[ZC_HS_SESSION_KEY_LEN];

    memcpy(IvSend, u8SessionKey, ZC_HS_SESSION_KEY_LEN);
    u32RetVal = SEC_PaddingCheck(pstruSecHead->u8SecType, ZC_HTONS(pstruSecHead->u16TotalMsg), &u16PaddingLen);
    
    if (ZC_RET_ERROR == u32RetVal)
    {
        return ZC_RET_ERROR;
    }

    u16Len = ZC_HTONS(pstruSecHead->u16TotalMsg) + sizeof(ZC_SecHead) + u16PaddingLen;    
    
    if (u16Len > MSG_BUFFER_MAXLEN)
    {
        return ZC_RET_ERROR;
    }

    pu8Buf = (u8 *)ZC_malloc(MSG_BUFFER_MAXLEN);

    if (NULL == pu8Buf)
    {
        return ZC_MALLOC_ERROR;
    }

    u32OutLen = u16Len;
    u16Len = ZC_HTONS(pstruSecHead->u16TotalMsg);

    AES_CBC_Encrypt(pu8PlainData, u16Len, 
        u8SessionKey, ZC_HS_SESSION_KEY_LEN, 
        IvSend, 16, 
        pu8Buf + sizeof(ZC_SecHead), &u32OutLen);
    
    pstruSecHead->u16TotalMsg = ZC_HTONS((u16)u32OutLen);

    memcpy(pu8Buf, (u8*)pstruSecHead, sizeof(ZC_SecHead));
    
    struParam.u8NeedPoll = 0;
    struParam.pu8AddrPara = g_pu8ClientAddr;
    g_struProtocolController.pstruMoudleFun->pfunSendUdpData(g_struLanInfo.fd, pu8Buf, u32OutLen + sizeof(ZC_SecHead), &struParam);

    ZC_free(pu8Buf);

    return ZC_RET_OK;
}
/*************************************************
* Function: ZC_SendMsgToClient
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void ZC_SendLicenseResp(u8 u8Status)
{
    u16 u16Len;
    ZC_SecHead struSechead;
    ZC_LieceseAuthStatus struStatus;
    memset(&struStatus, 0, sizeof(struStatus));
    u8 *pu8MsgBuf = (u8 *)ZC_malloc(100);

    if(NULL == pu8MsgBuf)
    {
        return;
    }

    struStatus.u8Status = u8Status;
    
    EVENT_BuildMsg(ZC_CODE_LAN_SET_LICENSE, 0, pu8MsgBuf, &u16Len, (u8 *)&struStatus, sizeof(struStatus));
    struSechead.u8SecType = ZC_SEC_ALG_AES;
    struSechead.u16TotalMsg = ZC_HTONS(u16Len);
    (void)ZC_SendMsgToClient(&struSechead, pu8MsgBuf);
    ZC_free(pu8MsgBuf);
}

/*************************************************
* Function: ZC_GetAuthStatus
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
u8 ZC_GetAuthStatus(void)
{
    return g_struLiceInfo.u8Status;
}
/*************************************************
* Function: ZC_ConfigResetAccess
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
s32 ZC_ConfigLicense(u8 *pu8License, u16 u16Len)
{
    if (NULL == pu8License || ZC_LICENSE_LEN != u16Len)
    {
        return ZC_PARA_ERROR;
    }

    ZC_Printf("ZC_ConfigLicense\n");
    ZC_LicenseInfo struInfo;
    
    memset(&struInfo, 0 ,sizeof(struInfo));
    memset(&g_struLiceInfo, 0 ,sizeof(g_struLiceInfo));
    
    memcpy(g_struLiceInfo.u8License, pu8License, u16Len);
    g_struLiceInfo.u32Crc = crc16_ccitt(pu8License, u16Len);

    g_struLiceInfo.u32MagicFlag = ZC_MAGIC_FLAG;
    /* 1,write */
    g_struProtocolController.pstruMoudleFun->pfunWriteLicense((u8 *)&g_struLiceInfo, sizeof(ZC_LicenseInfo));
    /* 2,read back */
    g_struProtocolController.pstruMoudleFun->pfunReadLicense((u8 *)&struInfo, sizeof(ZC_LicenseInfo));
    /* 3,compare */
    if (0 == memcmp(&g_struLiceInfo, &struInfo, sizeof(ZC_LicenseInfo)))
    {
        g_struLiceInfo.u8Status = ZC_AUTH_OK;
        return ZC_RET_OK;
    }
    else
    {
        return ZC_WRITE_LICENSE_ERROR;
    }
}

/*************************************************
* Function: ZC_LanSetLicense
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void ZC_LanSetLicense(u8 *pu8License, u16 u16Len)
{
    if (NULL == pu8License || ZC_LICENSE_LEN != u16Len)
    {
        return;
    }
    s32 ret;
    u8 u8Status;

    u32 u32i;

    for (u32i = 0; u32i < (u32)u16Len; u32i++)
    {
        ZC_Printf("%02x\t", pu8License[u32i]);
    }
    ZC_Printf("\n");

    for (u32i = 0; u32i < (u32)u16Len; u32i++)
    {
        ZC_Printf("%02x\t", g_struLiceInfo.u8License[u32i]);
    }
    ZC_Printf("\n");
    
    u8Status = ZC_GetAuthStatus();

    if (ZC_AUTH_OK == u8Status)
    {
        if (0 == memcmp((const char *)g_struLiceInfo.u8License, (const char *)pu8License, ZC_LICENSE_LEN))
        {
            ZC_Printf("License same\n");
            u8Status = ZC_AUTH_OK;
        }
        else 
        {
            ZC_Printf("License no used\n");
            u8Status = ZC_AUTH_LICENSE_NO_USED;
        }
        goto END;
    }
    else if (ZC_AUTH_ERROR == u8Status)
    {
        ZC_Printf("status error\n");
        goto END;
    }

    ret = ZC_ConfigLicense(pu8License, u16Len);

    if (ZC_RET_OK == ret)
    {
        ZC_Printf("ZC_ConfigLicense ok\n");
        u8Status = ZC_AUTH_OK;
    }
    else
    {
        ZC_Printf("ZC_ConfigLicense error\n");
        u8Status = ZC_AUTH_ERROR;
    }
END:

    ZC_SendLicenseResp(u8Status);
}
/*************************************************
* Function: ZC_LanCancelLicense
* Description:
* Author: cxy
* Returns:
* Parameter:
* History:
*************************************************/
void ZC_LanCancelLicense(void)
{
    ZC_Printf("ZC_LanCancelLicense\n");
    ZC_LicenseInfo struInfo;

    memset(&struInfo, 0, sizeof(ZC_LicenseInfo));

    g_struProtocolController.pstruMoudleFun->pfunWriteLicense((u8 *)&struInfo, sizeof(ZC_LicenseInfo));
    
}
/******************************* FILE END ***********************************/

