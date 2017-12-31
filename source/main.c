#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <3ds/types.h>
#include <3ds/srv.h>
#include <3ds/svc.h>
#include <3ds/services/APT.h>
#include <3ds/services/FS.h>
#include <3ds/services/GSPgpu.h>
#include "udsploit.h"
#include "safehax.h"

#define HID_PAD (*(vu32*)0x1000001C)

typedef enum
{
	PAD_A = (1<<0),
	PAD_B = (1<<1),
	PAD_SELECT = (1<<2),
	PAD_START = (1<<3),
	PAD_RIGHT = (1<<4),
	PAD_LEFT = (1<<5),
	PAD_UP = (1<<6),
	PAD_DOWN = (1<<7),
	PAD_R = (1<<8),
	PAD_L = (1<<9),
	PAD_X = (1<<10),
	PAD_Y = (1<<11)
}PAD_KEY;

int _strlen(char* str)
{
	int l=0;
	while(*(str++))l++;
	return l;
}

void _strcpy(char* dst, char* src)
{
	while(*src)*(dst++)=*(src++);
	*dst=0x00;
}

void _strappend(char* str1, char* str2)
{
	_strcpy(&str1[_strlen(str1)], str2);
}

Result _srv_RegisterClient(Handle* handleptr)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x10002; //request header code
	cmdbuf[1]=0x20;

	Result ret=0;
	if((ret=svcSendSyncRequest(*handleptr)))return ret;

	return cmdbuf[1];
}

Result _initSrv(Handle* srvHandle)
{
	Result ret=0;
	if(svcConnectToPort(srvHandle, "srv:"))return ret;
	return _srv_RegisterClient(srvHandle);
}

Result _srv_getServiceHandle(Handle* handleptr, Handle* out, char* server)
{
	u8 l=_strlen(server);
	if(!out || !server || l>8)return -1;

	u32* cmdbuf=getThreadCommandBuffer();

	cmdbuf[0]=0x50100; //request header code
	_strcpy((char*)&cmdbuf[1], server);
	cmdbuf[3]=l;
	cmdbuf[4]=0x0;

	Result ret=0;
	if((ret=svcSendSyncRequest(*handleptr)))return ret;

	*out=cmdbuf[3];

	return cmdbuf[1];
}

Result _GSPGPU_ImportDisplayCaptureInfo(Handle* handle, GSPGPU_CaptureInfo *captureinfo)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x00180000; //request header code

	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	ret = cmdbuf[1];

	if(ret==0)
	{
		memcpy(captureinfo, &cmdbuf[2], 0x20);
	}

	return ret;
}

u8 *GSP_GetTopFBADR()
{
	GSPGPU_CaptureInfo capinfo;
	u32 ptr;

	u32 *paramblk = (u32*)*((u32*)0xFFFFFFC);
	Handle* gspHandle=(Handle*)paramblk[0x58>>2];

	if(_GSPGPU_ImportDisplayCaptureInfo(gspHandle, &capinfo)!=0)return NULL;

	ptr = (u32)capinfo.screencapture[0].framebuf0_vaddr;
	if(ptr>=0x1f000000 && ptr<0x1f600000)return NULL;//Don't return a ptr to VRAM if framebuf is located there, since writing there will only crash.

	return (u8*)ptr;
}

Result GSP_FlushDCache(u32* addr, u32 size)
{
	Result (*_GSP_FlushDCache)(u32* addr, u32 size);
	u32 *paramblk = (u32*)*((u32*)0xFFFFFFC);
	_GSP_FlushDCache=(void*)paramblk[0x20>>2];
	return _GSP_FlushDCache(addr, size);
}

const u8 hexTable[]=
{
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

void hex2str(char* out, u32 val)
{
	int i;
	for(i=0;i<8;i++){out[7-i]=hexTable[val&0xf];val>>=4;}
	out[8]=0x00;
}


Result _GSPGPU_ReleaseRight(Handle handle)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x170000; //request header code

	Result ret=0;
	if((ret=svcSendSyncRequest(handle)))return ret;

	return cmdbuf[1];
}

const char* const aptServiceNames[] = {"APT:U", "APT:A", "APT:S"};

#define _aptSessionInit() \
	int aptIndex; \
	for(aptIndex = 0; aptIndex < 3; aptIndex++)	if(!_srv_getServiceHandle(srvHandle, &aptuHandle, (char*)aptServiceNames[aptIndex]))break;\
	svcCloseHandle(aptuHandle);\

#define _aptOpenSession() \
	svcWaitSynchronization(aptLockHandle, U64_MAX);\
	srvGetServiceHandle(&aptuHandle, (char*)aptServiceNames[aptIndex]);\

#define _aptCloseSession()\
	svcCloseHandle(aptuHandle);\
	svcReleaseMutex(aptLockHandle);\

void doGspwn(u32* src, u32* dst, u32 size)
{
	Result (*gxcmd4)(u32 *src, u32 *dst, u32 size, u16 width0, u16 height0, u16 width1, u16 height1, u32 flags);
	u32 *paramblk = (u32*)*((u32*)0xFFFFFFC);
	gxcmd4=(void*)paramblk[0x1c>>2];
	gxcmd4(src, dst, size, 0, 0, 0, 0, 0x8);
}

void clearScreen(u8 shade)
{
	u8 *ptr = GSP_GetTopFBADR();
	if(ptr==NULL)return;
	memset(ptr, shade, 240*400*3);
	GSP_FlushDCache((u32*)ptr, 240*400*3);
}

void errorScreen(char* str, u32* dv, u8 n)
{
	clearScreen(0x00);
	//renderString("FATAL ERROR",0,0);
	//renderString(str,0,10);
	if(dv && n)
	{
		int i;
	//	for(i=0;i<n;i++)drawHex(dv[i], 8, 50+i*10);
	}
	while(1);
}

void drawTitleScreen(char* str)
{
	clearScreen(0x00);
	//centerString(HAX_NAME_VERSION,0);
	//centerString(BUILDTIME,10);
	//centerString("smealum.github.io/ninjhax2/",20);
	//renderString(str, 0, 40);
}

// Result _APT_HardwareResetAsync(Handle* handle)
// {
// 	u32* cmdbuf=getThreadCommandBuffer();
// 	cmdbuf[0]=0x4E0000; //request header code
	
// 	Result ret=0;
// 	if((ret=svc_sendSyncRequest(*handle)))return ret;
	
// 	return cmdbuf[1];
// }

Result _APT_AppletUtility(Handle* handle, u32* out, u32 a, u32 size1, u8* buf1, u32 size2, u8* buf2)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x4B00C2; //request header code
	cmdbuf[1]=a;
	cmdbuf[2]=size1;
	cmdbuf[3]=size2;
	cmdbuf[4]=(size1<<14)|0x402;
	cmdbuf[5]=(u32)buf1;
	
	cmdbuf[0+0x100/4]=(size2<<14)|2;
	cmdbuf[1+0x100/4]=(u32)buf2;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	if(out)*out=cmdbuf[2];

	return cmdbuf[1];
}

Result _APT_NotifyToWait(Handle* handle, u32 a)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x430040; //request header code
	cmdbuf[1]=a;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	return cmdbuf[1];
}

Result _APT_CancelLibraryApplet(Handle* handle, u32 is_end)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x3b0040; //request header code
	cmdbuf[1]=is_end;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	return cmdbuf[1];
}

Result _APT_IsRegistered(Handle* handle, u32 app_id, u8* out)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x90040; //request header code
	cmdbuf[1]=app_id;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	if(out)*out = cmdbuf[2];

	return cmdbuf[1];
}

Result _APT_ReceiveParameter(Handle* handle, u32 app_id)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0xd0080; //request header code
	cmdbuf[1]=app_id;
	cmdbuf[2]=0x0;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	return cmdbuf[1];
}

Result _APT_Finalize(Handle* handle, u32 a)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x40040; //request header code
	cmdbuf[1]=a;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	return cmdbuf[1];
}

Result _APT_PrepareToCloseApplication(Handle* handle, u8 a)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x220040; //request header code
	cmdbuf[1]=a;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	return cmdbuf[1];
}

Result _APT_CloseApplication(Handle* handle, u32 a, u32 b, u32 c)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x270044; //request header code
	cmdbuf[1]=a;
	cmdbuf[2]=0x0;
	cmdbuf[3]=b;
	cmdbuf[4]=(a<<14)|2;
	cmdbuf[5]=c;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;

	return cmdbuf[1];
}

Result _APT_GetLockHandle(Handle* handle, u16 flags, Handle* lockHandle)
{
	u32* cmdbuf=getThreadCommandBuffer();
	cmdbuf[0]=0x10040; //request header code
	cmdbuf[1]=flags;
	
	Result ret=0;
	if((ret=svcSendSyncRequest(*handle)))return ret;
	
	if(lockHandle)*lockHandle=cmdbuf[5];
	
	return cmdbuf[1];
}

void _aptExit()
{
	Handle _srvHandle;
	Handle* srvHandle = &_srvHandle;
	Handle aptLockHandle = 0;
	Handle aptuHandle=0x00;

	_initSrv(srvHandle);

	_aptSessionInit();

	_aptOpenSession();
	_APT_GetLockHandle(&aptuHandle, 0x0, &aptLockHandle);
	_aptCloseSession();

	_aptOpenSession();
	_APT_CancelLibraryApplet(&aptuHandle, 0x1);
	_aptCloseSession();

	_aptOpenSession();
	_APT_NotifyToWait(&aptuHandle, 0x300);
	_aptCloseSession();

	u32 buf1;
	u8 buf2[4];

	_aptOpenSession();
	buf1 = 0x00;
	_APT_AppletUtility(&aptuHandle, NULL, 0x4, 0x1, (u8*)&buf1, 0x1, buf2);
	_aptCloseSession();

	u8 out = 1;
	while(out)
	{
		_aptOpenSession();
		_APT_IsRegistered(&aptuHandle, 0x401, &out); // wait until swkbd is dead
		_aptCloseSession();
	}

	_aptOpenSession();
	buf1 = 0x10;
	_APT_AppletUtility(&aptuHandle, NULL, 0x7, 0x4, (u8*)&buf1, 0x1, buf2);
	_aptCloseSession();

	_aptOpenSession();
	buf1 = 0x00;
	_APT_AppletUtility(&aptuHandle, NULL, 0x4, 0x1, (u8*)&buf1, 0x1, buf2);
	_aptCloseSession();


	_aptOpenSession();
	_APT_PrepareToCloseApplication(&aptuHandle, 0x1);
	_aptCloseSession();

	_aptOpenSession();
	_APT_CloseApplication(&aptuHandle, 0x0, 0x0, 0x0);
	_aptCloseSession();

	svcCloseHandle(aptLockHandle);
}

Result _GSPGPU_SetBufferSwap(Handle handle, u32 screenid, GSPGPU_FramebufferInfo framebufinfo)
{
	Result ret=0;
	u32 *cmdbuf = getThreadCommandBuffer();

	cmdbuf[0] = 0x00050200;
	cmdbuf[1] = screenid;
	memcpy(&cmdbuf[2], &framebufinfo, sizeof(GSPGPU_FramebufferInfo));
	
	if((ret=svcSendSyncRequest(handle)))return ret;

	return cmdbuf[1];
}

int main(int loaderparam, char** argv)
{

	srvInit();

	u32 *paramblk = (u32*)loaderparam;

	Handle* gspHandle=(Handle*)paramblk[0x58>>2];
	u32* linear_buffer = (u32*)((((u32)paramblk) + 0x1000) & ~0xfff);

	// put framebuffers in linear mem so they're writable
	u8* top_framebuffer = &linear_buffer[0x00100000/4];
	u8* low_framebuffer = &top_framebuffer[0x00046500];
	_GSPGPU_SetBufferSwap(*gspHandle, 0, (GSPGPU_FramebufferInfo){0, (u32*)top_framebuffer, (u32*)top_framebuffer, 240 * 3, (1<<8)|(1<<6)|1, 0, 0});
	_GSPGPU_SetBufferSwap(*gspHandle, 1, (GSPGPU_FramebufferInfo){0, (u32*)low_framebuffer, (u32*)low_framebuffer, 240 * 3, 1, 0, 0});

	// TODO: visual indicator (fill)

	udsploit();
	hook_kernel();
	safehax();

	svcSleepThread(100000000); //sleep long enough for memory to be written

	// TODO as above
	
	//disable GSP module access
	_GSPGPU_ReleaseRight(*gspHandle);
	svcCloseHandle(*gspHandle);

	//exit to menu
	_aptExit();

	svcExitProcess();

	while(1);
	return 0;
}
