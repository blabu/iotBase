/*
 * transportNRF24Server.h
 *
 *  Created on: 5 мая 2018 г.
 *      Author: blabu
 */

#include "nrf24.h"
#include "nrf24AppLayer.h"
#include "logging.h"
#include "MyString.h"
#include "initLowLevelModule.h"
#include "transportServer.h"
#include "PlatformSpecific.h"
#include "config.h"
#include "usbd_cdc_if.h"

#ifdef SERVER
/*
 * Модуль всегда находится в режиме приема
 * Когда нужно что-то передать переключаемся на передатчик
 * и в конце обязательно возвращаемся на прием
 * */

#define MAX_CHANNEL 4

typedef struct {
		bool_t isBusy;
		bool_t isReady;
		u08 pipeNumber;
		channel_t pipe;
		byte_ptr buff;
} channelBuff_t;

static channelBuff_t receiveBuf[MAX_CHANNEL];

static void socetReceivePacet(BaseSize_t pipeNumber, BaseParam_t buff) {
	if(pipeNumber > MAX_CHANNEL) writeLogStr("ERROR: overflow pipe number\r\n");
	if(!receiveBuf[pipeNumber].isBusy) {
		writeLogStr("+");
		receiveBuf[pipeNumber].isReady = TRUE;
	}
	receiveBuf[pipeNumber].buff = buff;
	writeLogU32(pipeNumber);
}

// Устройство в режиме сервера всегда работает как приемник
void initTransportLayer(u08 channel, byte_ptr addrHeader) {
    nRF24_Init();
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	nRF24_CE_L();
	for(u08 i = 0; i<MAX_CHANNEL; i++) {
		receiveBuf[i].isReady = FALSE;
		receiveBuf[i].isBusy  = FALSE;
		receiveBuf[i].buff = NULL;
		receiveBuf[i].pipeNumber = i;
		receiveBuf[i].pipe.address[0] = i+1;  // Server address 1_5
		receiveBuf[i].pipe.address[1] = addrHeader[3]; // Server address 1_1
		receiveBuf[i].pipe.address[2] = addrHeader[2]; // Server address 1_2
		receiveBuf[i].pipe.address[3] = addrHeader[1]; // Server address 1_3
		receiveBuf[i].pipe.address[4] = addrHeader[0]; // Server address 1_4
		receiveBuf[i].pipe.channel = channel;
		receiveBuf[i].pipe.dataLength = 32;
		if(i) {
			registerCallBack((TaskMng)RXModeRetry,receiveBuf[i].pipeNumber,(BaseParam_t)(&receiveBuf[i].pipe),(u32*)RXModeRetry+receiveBuf[i-1].pipeNumber);
		}
	}
	SetTask(configureNRF24,nRF24_DR_250kbps,NULL);
	registerCallBack((TaskMng)RXModeRetry,receiveBuf[0].pipeNumber,(BaseParam_t)(&receiveBuf[0].pipe),configureNRF24);
	registerCallBack((TaskMng)FinishInitMultiReceiver,0, 0, (u32*)RXModeRetry+receiveBuf[MAX_CHANNEL-1].pipeNumber);
	changeCallBackLabel(initTransportLayer,FinishInitMultiReceiver);
	connectTaskToSignal(socetReceivePacet,(void*)signalNrf24ReceiveMessages);
}

static void offSession(BaseSize_t id, BaseParam_t arg_p) {
	if(id > MAX_CHANNEL) {
		execCallBack(((void*)(u32*)offSession+id));
		return;
	}
	u08 i = id-1;
	receiveBuf[i].isBusy = FALSE;
	receiveBuf[i].buff = NULL;
	execCallBack(((void*)(u32*)offSession+id));
}

static void EnableTransmitter(u16 id,  ClientData_t *data) {
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	u08 i = id-1;
	updateTimer(offSession,id,NULL,TICK_PER_SECOND<<2); // Таймоут для очистки передатчика
	changeCallBackLabel((void*)((u32*)EnableTransmitter+id),TXModeRetry);
	SetTask((TaskMng)TXModeRetry,0,(BaseParam_t)&receiveBuf[i].pipe);
	return;
}

static void DisableTransmitter(u16 id,  ClientData_t *data) {
	nRF24_SetPowerMode(nRF24_PWR_DOWN);
	u16 i = id-1;
	SetTask((TaskMng)RXModeRetry,receiveBuf[i].pipeNumber,(BaseParam_t)&receiveBuf[i].pipe);
	registerCallBack((TaskMng)FinishInitMultiReceiver,0,0,(u32*)RXModeRetry+receiveBuf[i].pipeNumber);
	changeCallBackLabel((u32*)DisableTransmitter+id,FinishInitMultiReceiver);
	return;
}

static void Send(u16 id,  ClientData_t *data) {
	u08 i = id-1;
	changeCallBackLabel((void*)((u32*)Send+id),TransmitPacket);
	SetTimerTask(TransmitPacket,receiveBuf[i].pipe.dataLength,data->second,2); // Необходимо заполнить весь буфер (можно мусором)
	return;
}

// Функция непосредственной отправки данных
// Устройство всегда работает на прием информации (за исключение необходимости передать что-то)
void sendToClient(u16 id,  ClientData_t *data) {
	if(id > MAX_CHANNEL) { execCallBack((void*)((u32*)sendToClient + id)); return;}
	u08 i = id-1;
	if(!receiveBuf[i].isBusy) {execCallBack((void*)((u32*)sendToClient + id)); return;}
	SetTask((TaskMng)EnableTransmitter,id,(BaseParam_t)data);
	registerCallBack((TaskMng)Send,id,(BaseParam_t)data,(void*)((u32*)EnableTransmitter+id));
	registerCallBack((TaskMng)DisableTransmitter,id,(BaseParam_t)data,(void*)((u32*)Send+id));
	changeCallBackLabel((void*)((u32*)sendToClient + id),(void*)((u32*)DisableTransmitter+id));
}

// Функция получения данных полученные данные будут записаны по указателю result, но не более размера size
void receiveFromClient(u16 id, ClientData_t *result) {
	if(id > MAX_CHANNEL) {
		// Здесь мы быть не должны
		writeLogStr("ERROR: Incorrect session Id\r\n");
		execCallBack((void*)((u32*)receiveFromClient + id));
		return;
	}
	u08 i = id-1;
	if(receiveBuf[i].buff != NULL) { // Если есть данные
		updateTimer(offSession,id,NULL,TICK_PER_SECOND<<2);
		memCpy(result->second,receiveBuf[i].buff,result->first); // Читаем ровно столько сколько попросили
		receiveBuf[i].buff = NULL; // Обнуляем буфер для получения следующих данных
		execCallBack((void*)((u32*)receiveFromClient + id));
		return;
	} else if (!receiveBuf[i].isBusy) {
		execCallBack((void*)((u32*)receiveFromClient + id));
		return;
	}
	writeLogStr(".");
	SetTimerTask((TaskMng)receiveFromClient,id,(BaseParam_t)result,TIME_DELAY_IF_BUSY);
	return;
}

// Вернет идентификатор следующего готового узла для работы. (0 означает, что нет готовых узлов)
u16 getNextReadyDevice() {
	static char buf[10];
	for(u08 i = 0; i<MAX_CHANNEL; i++) {
		if(receiveBuf[i].isReady) {
			receiveBuf[i].isReady = FALSE;
			receiveBuf[i].isBusy = TRUE;
			SetTimerTask(offSession,i+1,NULL,TICK_PER_SECOND<<2);
			strClear(buf); strCat(buf,"RDY:"); toStringDec(i,buf+strSize("RDY:")); writeLogStr(buf);
			return i+1;
		}
	}
	return 0;
}

void updateDevice(Device_t* dev) {
	static char str[47];  //NEW=S;XXXX;YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY;\r\n
	char tempStr[6];
	strClear(str);
	if(dev->isSecure) strCat(str, "UP=1;");
	else strCat(str, "UP=0;");
	toString(2,dev->Id,str+6);
	strCat(str, ";");
	for(u08 i = 0; i<16; i++) {
		toString(1,dev->Key[i],tempStr);
		strCat(str,tempStr);
	}
	strCat(str,";\r\n");
	CDC_Transmit_FS((byte_ptr)str,strSize(str));
	execCallBack((u32*)updateDevice + dev->Id);
}

void addNewDevice(Device_t* dev) {
	static char str[47];  //NEW=S;XXXX;YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY;\r\n
	char tempStr[6];
	strClear(str);
	if(dev->isSecure) strCat(str, "NEW=1;");
	else strCat(str, "NEW=0;");
	toString(2,dev->Id,str+6);
	strCat(str, ";");
	for(u08 i = 0; i<16; i++) {
		toString(1,dev->Key[i],tempStr);
		strCat(str,tempStr);
	}
	strCat(str,";\r\n");
	CDC_Transmit_FS((byte_ptr)str,strSize(str));
	execCallBack((u32*)addNewDevice + dev->Id);
}

void serializeDevice(string_t devStr, Device_t* d) {
	if(devStr == NULL || d == NULL) return;
	char tempStr[6];
	strClear(devStr);
	toString(1,d->isSecure,tempStr);
	strCat(devStr,tempStr);
	strCat(devStr,";");
	toString(2,d->Id,tempStr);
	strCat(devStr,tempStr);
	strCat(devStr,";");
	for(u08 i = 0; i<KEY_SIZE; i++) {
		toString(1,d->Key[i],tempStr);
		strCat(devStr,tempStr);
	}
	strCat(devStr,";\r\n");
}

// Вернет -1
s08 deserializeDevice(string_t devStr, Device_t* d) {
	if(devStr == NULL || d == NULL) return -1;
	u08 c = strSplit(';',devStr);
	if(c<3) return -1;
	d->isSecure = toInt08(devStr);
	devStr += strSize(devStr);
	d->Id = toInt32(devStr);
	devStr += strSize(devStr);
	char tempStr[4];
	for(u08 i = 0; i<KEY_SIZE; i++) {
		tempStr[0] = devStr++;
		tempStr[1] = devStr++;
		tempStr[3] = 0;
		d->Key[i] = toInt16(tempStr);
	}
}

//Функция получения параметров из памяти. Должна расположить данные по переданным указателям
void getAllParameters(ListNode_t* DeviceList) {
	execCallBack(getAllParameters);
}

#endif
