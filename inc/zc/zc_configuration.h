/**
******************************************************************************
* @file     zc_configuration.h
* @authors  cxy
* @version  V1.0.0
* @date     10-Sep-2014
* @brief    configuration module
******************************************************************************
*/

#ifndef  __ZC_CONFIGURATION_H__ 
#define  __ZC_CONFIGURATION_H__
#include <zc_common.h>
#include <zc_protocol_interface.h>

#define    ZC_GET_TYPE_CLOUDKEY    (0)
#define    ZC_GET_TYPE_DEVICEID    (1)
#define    ZC_GET_TYPE_DOMAIN      (2)
#define    ZC_GET_TYPE_PRIVATEKEY  (3)
#define    ZC_GET_TYPE_VESION      (4)
#define    ZC_GET_TYPE_TOKENKEY    (5)

#define    ZC_MAGIC_FLAG (0x04083207)

typedef enum
{
    ZC_AUTH_NONE  =  0,                    /* 未授权                        */
    ZC_AUTH_OK    =  1,                    /* 已授权，授权成功              */
    ZC_AUTH_ERROR =  2,                    /* 已授权，授权失败              */
    ZC_AUTH_LICENSE_NO_USED = 3,         /* 已授权，该license未被使用     */
    ZC_AUTHING    =  4                    /* 正在被授权                    */
}ZC_EnumAuthStatus;

typedef struct 
{
    u32 u32TraceSwitch;     //Trace data switch, 1:open, 0:close,default 0
    u32 u32SecSwitch;       //Sec data switch, 1:open, 0:close, 2:close RSA, default 1
    u32 u32WifiConfig;      //Use Config SSID,password,1:open, 0:close, default 0
    u32 u32ServerAddrConfig;  //connect with test url,0:dns, 1:use u32IpAddr, default 0

    u8 u8Ssid[ZC_SSID_MAX_LEN];
    u8 u8Password[ZC_PASSWORD_MAX_LEN];

    u32 u32ServerIp;        //use if wifconfig is 1;
    u16 u16ServerPort;      //use if wifconfig is 1;
    u16 u16Pad;      //use if wifconfig is 1;
}ZC_SwitchInfo;

typedef struct 
{
    u8 u8CloudKey[ZC_CLOUD_KEY_MAX_LEN];
    u8 u8CloudAddr[ZC_CLOUD_ADDR_MAX_LEN];
    u8 u8TokenKey[ZC_HS_SESSION_KEY_LEN];
}ZC_CloudInfo;

typedef struct 
{
    u8 u8PrivateKey[ZC_MODULE_KEY_LEN];
    u8 u8DeviceId[ZC_HS_DEVICE_ID_LEN];
    u8 u8Domain[ZC_DOMAIN_LEN];
    u8 u8EqVersion[ZC_EQVERSION_LEN];
}ZC_RegisterInfo;

typedef struct
{
    u32 u32MagicFlag;
    u8 u8Ssid[ZC_SSID_MAX_LEN];
    u8 u8Password[ZC_PASSWORD_MAX_LEN];
}ZC_ConnectionInfo;

typedef struct
{
    u32  u32UnBindFlag;//use if u32UnBindFlag is 1;
    u32  u32UnBcFlag;    
}ZC_DeviceInfo;

typedef struct 
{
    u32 u32Crc;
    ZC_ConnectionInfo struConnection;//100 byte
    ZC_CloudInfo    struCloudInfo; // 70byte
    ZC_SwitchInfo   struSwitchInfo;//120byte
    ZC_DeviceInfo   struDeviceInfo;//8byte
}ZC_ConfigDB;

typedef struct
{
    u32 u32MagicFlag;
    u32 u32Crc;
    u8  u8License[ZC_LICENSE_LEN];
    u8  u8Status;
    u8  u8pad[2];
}ZC_LicenseInfo;

typedef struct
{
    int fd;
    u8 u8TokenKey[ZC_HS_SESSION_KEY_LEN];
    u8 IvSend[ZC_HS_SESSION_KEY_LEN];
    u8 IvRecv[ZC_HS_SESSION_KEY_LEN];
}ZC_LanConfigInfo;

typedef struct
{
    u8 u8Status;               /* 授权状态，具体参考ZC_EnumAuthStatus */
    u8 u8pad[3];
}ZC_LieceseAuthStatus;

extern ZC_ConfigDB g_struZcConfigDb;
extern ZC_RegisterInfo g_struRegisterInfo;
extern ZC_LicenseInfo g_struLiceInfo;

#ifdef __cplusplus
extern "C" {
#endif

void ZC_ConfigInitPara(void);
void ZC_ConfigPara(u8 *pu8Data);
void ZC_StoreRegisterInfo(u8 *pu8Data,u16 u16DataLen,u8 u8RegisterFlag);
void ZC_StoreTokenKey(u8 *pu8Data);
void ZC_StoreConnectionInfo(u8 *pu8Ssid, u8 *pu8Password);
void ZC_GetStoreInfor(u8 u8Type, u8 **pu8Data);
void ZC_StoreAccessInfo(u8 *pu8ServerIp, u8 *pu8ServerPort);
void ZC_ConfigUnBind(u32 u32UnBindFlag);
void ZC_ConfigReset(void);
void ZC_ConfigResetAccess(void);
s32 ZC_ConfigLicense(u8 *pu8License, u16 u16Len);
u8 ZC_GetAuthStatus(void);
void ZC_LanSetLicense(u8 *pu8License, u16 u16Len);
void ZC_LanCancelLicense(void);


#ifdef __cplusplus
}
#endif
#endif
/******************************* FILE END ***********************************/

