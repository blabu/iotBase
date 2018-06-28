/*
0 * ApplicationLayer.c
 *
 *  Created on: Mar 22, 2018
 *      Author: okh
 */


#include "PlatformSpecific.h"
#include "IotProtocolClient.h"
#include "ApplicationLayer.h"
#include "transportClient.h"
#include "initLowLevelModule.h"
#include "MyString.h"
#include "config.h"
#include "logging.h"
#include "led.h"
#include "crypt.h"

/* .
 * .
 * .
 * */
#ifndef SERVER
/* Регистрация устройства по его типу в системе. Выполняется без шифрования
 * Заполнит поле CryptKey ключом шифрования используется AES128
 */

static ClientData_t serverID;

void Register(BaseSize_t type, BaseParam_t buffer){
	static u08 count = 0;
	byte_ptr buff = (byte_ptr)buffer;
	u16 id = 0;
	switch(count) {
	case 0: // Запрос на регистрацию
		if(type == 0) {
			execCallBack(Register);
			return;
		}
		LED_ON();
		writeLogStr("TRY REG:");
		//writeLogByteArray(5, serverID.second);
		GetLastStatus();
		if(buff != NULL) freeMem(buff);
		buff = allocMem(2+KEY_SIZE+1); // Идентификатор (два байта) + Ключ + запасной байт
		if(buff == NULL) {
			execCallBack(Register);
			return;
		}
		memCpy(buff,"GET_ID?",strSize("GET_ID?")); // Текст запроса
		setId(type);
		setSecurity(FALSE);
		count++;
		registerCallBack(Register,type,(BaseParam_t)buff,ReadClient);
		SetTask((TaskMng)ReadClient,getAllocateMemmorySize(buff), (BaseParam_t)buff);
		return;
	case 1: // Анализ ответа
		id = *((u16*)buff); // Первые два байта это идентификатор
		if((id>>8) != type) {
			count = 0xFF;
			writeLogStr("ERROR: Reg\r\n");
			SetTask(Register,type,(BaseParam_t)buff);
			return;
		}
		count++;
		registerCallBack(Register,type,(BaseParam_t)buff,saveParameters);
		saveParameters(id, buff+2, KEY_SIZE, FALSE);
		return;
	case 2:
	default:
		count = 0;
		LED_OFF();
		freeMem(buff);
		execCallBack(Register);
		return;
	}
}

void FindServer(BaseSize_t count, BaseParam_t maxTry) {
	static u08 serverChannel;
	byte_ptr mxTry = (byte_ptr)maxTry;
	switch(count) {
	case 0:
		setSeed(getTick() + maxTry);
		serverChannel = RandomSimple() & 0x7F; // Генерируем случайный канал от 0 до 127
		if(serverID.second != NULL) freeMem(serverID.second);
		serverID.second = allocMem(10); serverID.first = 10;
		if(serverID.second == NULL) {count = 0xff; break;}
		else count++;
		memSet(serverID.second,6,0);
		// no break;
	case 1:
		LED_ON();
		if(*mxTry == 0) {
			writeLogStr("Too many");
			count = 0xFF;
			break;
		}
		count++;
		*mxTry = *mxTry-1;
		char temp[20];
		temp[0] = 0;
		strCat(temp,"TRY find server ");
		toStringDec(serverChannel,temp+strSize(temp));
		temp[19] = 0;
		writeLogTempString(temp);
		registerCallBack(FindServer,count, mxTry, ScanEfire);
		SetTimerTask((TaskMng)ScanEfire,serverChannel,&serverID,10);
		return;
	case 2:
		if(serverID.second[1] != 0 &&
		   serverID.second[2] != 0 &&
		   serverID.second[3] != 0) {// Нашли сервер
			LED_OFF();
			serverID.second[0] = 2;
			changeCallBackLabel(FindServer,initTransportLayer);
			SetTimerTask((TaskMng)initTransportLayer,serverChannel,serverID.second, TICK_PER_SECOND<<4);
			writeLogByteArray(5,serverID.second);
			return;
		}
		if(serverChannel > 0x7F) serverChannel=0;
		else serverChannel++; // НЕ НАШЛИ
		count--; // Пытаемся поиcкать в другом канале
		break;
	default:
		LED_OFF();
		serverChannel = 0;
		freeMem(serverID.second);
		execCallBack(FindServer);
		return;
	}
	SetTimerTask(FindServer,count,mxTry,TIME_DELAY_IF_BUSY<<1);
}

#endif
