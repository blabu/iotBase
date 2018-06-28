/*
 * IotProtocolServer.c
 *
 *  Created on: Mar 28, 2018
 *      Author: okh
 */

#include "initLowLevelModule.h"
#include "IotProtocolServer.h"
#include "transportServer.h"
#include "frame.h"
#include "crypt.h"
#include "List.h"
#include "logging.h"
#include "MyString.h"
#include "config.h"

#ifndef NULL
#define NULL 0
#endif

static byte_ptr servID = NULL; // Для ПИНГА
static ListNode_t* DeviceList = NULL; // Хранит указатель на голову списка устройств
static TaskMng WriteHandler = NULL;
static TaskMng ReadHandler = NULL;
static bool_t isAllowRegistration = FALSE;

void allowRegistration(bool_t isEnable) {
	isAllowRegistration = isEnable;
}

static Device_t* findDeviceById(u16 devId) {
	Device_t* result = NULL;
	ListNode_t* head = findHead(DeviceList);
	if(head == NULL) return result;
	while( (head = head->next) != NULL ) {
		if(head->data == NULL) break;
		result = ((Device_t*)(head->data));
		if( result->Id == devId ) break;
		result = NULL;
	}
	return result;
}

static u08 getTypeById(u16 id) {
	return (u08)(id>>8);
}

static u16 generateNewId(u08 type) {
	u16 temp = 0;
	do {
		temp = RandomSimple() & 0xFF;
		temp |= (u16)(type<<8);
	} while(findDeviceById(temp) != NULL);
	return temp;
}

static void generateKey(byte_ptr key) {
	for(u08 i = 0; i<KEY_SIZE; i+=4) {
		u32 temp = RandomSimple();
		*((u32*)(key+i)) = temp;
	}
}

static void freeClient(BaseSize_t sessionId, Client_t* c) {
	writeLogWhithStr("Free session:", sessionId);
	freeMem(c->buff.second);
	freeMem(c->newKey);
	freeMem((byte_ptr)c);
	execCallBack((u32*)freeClient+sessionId);
}

static void freeClientData(BaseSize_t sessionId, ClientData_t* d) {
	freeMem(d->second);
	freeMem((byte_ptr)d);
}

static void ClientWork(BaseSize_t count, BaseParam_t client);

static void NewDeviceCreate(BaseSize_t count, BaseParam_t client) {
	u08 buff[PROTOCOL_BUFFER_SIZE];
	Client_t* cl = (Client_t*)client;
	message_t msg;
	switch(count) {
	case 0:
		generateKey(cl->dev->Key);
		cl->dev->Id = generateNewId(cl->dev->Id);
		if(putToEndList(DeviceList,(void*)cl->dev, sizeof(Device_t)) == NULL) { // Записываем новое устройство в список всех устройств
			writeLogStr("ERROR: DeviceList overflow\r\n");
			count = 0xFF;
			break;
		}
		count++;
		// no break;
	case 1: //Формируем ответ клиенту с генерированными данными
		memCpy(buff, &(cl->dev->Id), sizeof(cl->dev->Id)); // Копируем в ответ клиенту идентификатор
		memCpy(buff+sizeof(cl->dev->Id),cl->dev->Key, KEY_SIZE); //Копируем в ответ клиенту ключ шифрования
		 // Отправляем запрос без шифрования если это вновь зарегистрированное устройство
		msg.data = buff;
		msg.dataSize = sizeof(cl->dev->Id)+KEY_SIZE;
		msg.isWrite = 1;
		msg.version = 0;
		msg.deviceID = getTypeById(cl->dev->Id);
		u16 sz = formFrame(cl->buff.first, cl->buff.second,&msg);
		if(sz) {
			cl->buff.first = sz;
			count++;
			registerCallBack(NewDeviceCreate,count,(BaseParam_t)cl,(void*)((u32*)sendToClient + cl->sessionId));
			SetTask((TaskMng)sendToClient, cl->sessionId, (BaseParam_t)(&cl->buff));
			return;
		}
		else {
			writeLogStr("ERROR: Can not form frame for new dev\r\n");
			execCallBack((void*)((u32*)NewDeviceCreate + cl->sessionId));
			return;
		}
	case 2: // Ожидаем подтверждения получения нового ключа шифрования
		count++;
		registerCallBack(NewDeviceCreate,count, (BaseParam_t)cl, (void*)((u32*)receiveFromClient+cl->sessionId));
		SetTask((TaskMng)receiveFromClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	case 3: //
		count=5; //TODO Перескакиваем отправку ОК
		msg.data = buff;
		msg.dataSize = PROTOCOL_BUFFER_SIZE;
		sz = parseFrame(getAllocateMemmorySize(cl->buff.second),cl->buff.second,&msg);
		if(sz > 0 && findStr(OK,(string_t)msg.data) >= 0) { // подтверждение отправляется без шифрования
			count++;
			registerCallBack(NewDeviceCreate,count,(BaseParam_t)cl, (u32*)addNewDevice+cl->dev->Id);
			cl->dev->isSecure = TRUE;
			addNewDevice(cl->dev); // Сохраняем новое устройство
			return;
		}else {
			freeMem((void*)cl->dev);
			writeLogStr("ERROR: REG OK not find\r\n");
			count = 0xFF;
			break;
		}
		break;
	case 4:
		msg.data = (byte_ptr)OK;
		msg.dataSize = strSize(OK);
		msg.deviceID = cl->dev->Id;
		msg.isWrite = TRUE;
		msg.version = 0;
		if(!formFrame(cl->buff.first,cl->buff.second,&msg)) {
			count = 0xFF;
			break;
		}
		changeCallBackLabel((void*)((u32*)NewDeviceCreate+ cl->sessionId), (void*)((u32*)sendToClient+cl->sessionId));
		SetTask((TaskMng)sendToClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	default:
		execCallBack((void*)((u32*)NewDeviceCreate + cl->sessionId));
		return;
	}
	SetTask(NewDeviceCreate,count,(BaseParam_t)cl);
}

static void DeviceWriteWork(BaseSize_t count, BaseParam_t client) { // Работа с найденым устройством из списка
	Client_t* cl = (Client_t*)client;
	message_t msg;
	u08 tempBuff[KEY_SIZE];
	ClientData_t* d;
	switch(count) {
	case 0:
		count++;
		if(WriteHandler != NULL) { // Копируем полученные данные и отправляем на анализ
			d = (ClientData_t*)allocMem(sizeof(ClientData_t));  // Выделяем память под наши данные
			if(d != NULL) {
				d->first = cl->buff.first;
				d->second = allocMem(d->first);
				if(d->second == NULL) {
					freeMem((byte_ptr)d);
					count = 0xFF;
					break; // Если выделить не удалось отправляем новый ключ
				}
				memCpy(d->second,cl->buff.second,d->first); // Копируем данные
				registerCallBack((TaskMng)freeClientData, cl->sessionId, d, ((u32*)WriteHandler+cl->dev->Id)); // Ставим колбэк для очистки памяти
				SetTask(WriteHandler, cl->dev->Id, (BaseParam_t)(d)); // Отправляем данные на анализ
			}
			break; // Здесь продолжим работу Отправим новый ключ
		} else {
			writeLogStr("ERROR: WriteHandler undef\r\n");
			count = 0xFF;
		}
		break;
	case 1: // Генерируем, шифруем и отправляем новый ключ шифрования
		cl->buff.first = getAllocateMemmorySize(cl->buff.second);
		cl->newKey = allocMem(KEY_SIZE);
		if(cl->newKey == NULL) {
			count=0xFF;
			break;
		}
		generateKey(cl->newKey);
		// Эти данные равны длине ключа шифрования
		if(cl->dev->isSecure) AesEcbEncrypt(cl->newKey,cl->dev->Key,tempBuff); // Шифруем старым ключом
		else memCpy(tempBuff,cl->newKey,KEY_SIZE);
		msg.data = tempBuff;
		msg.isWrite = TRUE;
		msg.dataSize = KEY_SIZE;
		if(cl->dev->isSecure) msg.version = 1;
		else msg.version = 0;
		msg.deviceID = cl->dev->Id;
		if(!formFrame(cl->buff.first,cl->buff.second,&msg)){
			writeLogStr("ERROR: Can not form frame");
			count = 0xFF;
			break;
		}
		count++;
		registerCallBack(DeviceWriteWork,count,(BaseParam_t)cl, (void*)((u32*)sendToClient+cl->sessionId));
		SetTask((TaskMng)sendToClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	case 2: // Ожидаем подтверждения получения нового ключа шифрования
		count++;
		registerCallBack(DeviceWriteWork,count, (BaseParam_t)cl, (void*)((u32*)receiveFromClient+cl->sessionId));
		SetTask((TaskMng)receiveFromClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	case 3: // Ожидаем ОК шифрованный
		count=5; // TODO Перескакиваем отправку ОК
		msg.data = tempBuff;
		msg.dataSize = KEY_SIZE;
		if(parseFrame(getAllocateMemmorySize(cl->buff.second),cl->buff.second,&msg) > 0) {
			switch(msg.version) {
				case 0:  cl->dev->isSecure = FALSE; break;
				case 1:  cl->dev->isSecure = TRUE; break;
				default: cl->dev->isSecure = FALSE;
			}
			u08 temp[KEY_SIZE]; // OK это не большой объем данных (размера в один ключ хватит с головой)
			if(cl->dev->isSecure) AesEcbDecrypt(msg.data,cl->newKey,temp);
			else memCpy(temp,msg.data,KEY_SIZE);
			if(findStr(OK,(string_t)temp) >= 0) { // подтверждение отправляется без шифрования
				cl->dev->isSecure = cl->isSecureSession;
				memCpy(cl->dev->Key,cl->newKey,KEY_SIZE);
				registerCallBack(DeviceWriteWork,count, (BaseParam_t)cl, (u32*)updateDevice + cl->dev->Id);
				updateDevice(cl->dev);
				writeLogStr("TX OK finded\r\n");
				return;
			}else {
				count = 0xFF;
				cl->dev->isSecure = FALSE; // Ошибка в передачи ключа в следующей передачи ключ не шифруем
				writeLogStr("ERROR: TX not OK\r\n");
			}
		}
		else {
			count = 0xFF;
			cl->dev->isSecure = FALSE; // Ошибка в передачи ключа в следующей передачи ключ не шифруем
			writeLogStr("ERROR: Parse not ok\r\n");
		}
		break;
	case 4: // Отправляем ОК (для надежности)
		msg.data = (byte_ptr)OK;
		msg.dataSize = strSize(OK);
		msg.deviceID = cl->dev->Id;
		msg.isWrite = TRUE;
		if(cl->dev->isSecure) msg.version = 1;
		else msg.version = 0;
		while((msg.dataSize & 0x0F) & 0x0F) msg.dataSize++;
		if(cl->dev->isSecure) {
			AesEcbEncrypt(msg.data,cl->dev->Key,tempBuff);
			msg.data = tempBuff;
		}
		if(!formFrame(cl->buff.first,cl->buff.second,&msg)) {
			writeLogStr("ERROR: Can not form frame");
			count = 0xFF;
			break;
		}
		changeCallBackLabel((void*)((u32*)DeviceWriteWork + cl->sessionId), (void*)((u32*)sendToClient+cl->sessionId));
		SetTask((TaskMng)sendToClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	default:
		execCallBack((void*)((u32*)DeviceWriteWork + cl->sessionId));
		return;
	}
	SetTask(DeviceWriteWork,count,(BaseParam_t)cl);
}

static void DeviceReadWork(BaseSize_t count, BaseParam_t client) { // Работа с найденым устройством из списка
	Client_t* cl = (Client_t*)client;
	u16 askSize = 0;
	u08 tempArray[PROTOCOL_BUFFER_SIZE];
	message_t msg;
	switch(count) {
	case 0: // Анализ размера запрашиваемого сообщения
		if(ReadHandler != NULL) {
		    askSize = (u16)toInt32((string_t)(cl->buff.second)); // Определяем размер запрашиваемой информации
			cl->buff.first = getAllocateMemmorySize(cl->buff.second); // Обновляем значение размера буфера
			if(askSize > cl->buff.first && askSize < PROTOCOL_BUFFER_SIZE) { // Если размера буфера не достаточно, перевыделяем его.
				byte_ptr tempBuff;
				tempBuff = cl->buff.second;
				cl->buff.second = allocMem(askSize);
				if(cl->buff.second == NULL) {
					cl->buff.second = tempBuff;
					count= 0xFF;
					break;
				}
				memCpy(cl->buff.second,tempBuff,cl->buff.first);
				freeMem(tempBuff);
			}
			count++;
			cl->buff.first = askSize; // Вписываем запрашиваемй размер буфера во входные параметры колбэка
			registerCallBack(DeviceReadWork,count,(BaseParam_t)cl, (u32*)ReadHandler+cl->dev->Id); // Ожидаем ответа
			SetTask(ReadHandler, cl->dev->Id, (BaseParam_t)(&cl->buff));
			return; // Ожидаем колбэк со сформированным ответом
		}
		count = 0xFF;
		break;
	case 1: // в cl->buf.second содержится ответ
		askSize = cl->buff.first; // Сохраняем запрашиваемый размер буфера (этот размер мы и передадим)
		cl->buff.first = getAllocateMemmorySize(cl->buff.second); // Востанавливаем исходный размер буфера
		while((askSize & 0x0F) & 0x0F) askSize++; // Дополняем размер до кратного 16-ти байт (размер блока)
		if(askSize > PROTOCOL_BUFFER_SIZE) {askSize = PROTOCOL_BUFFER_SIZE;}
		for(u08 i = 0; i<askSize; i+=KEY_SIZE) {
			if(cl->dev->isSecure) AesEcbEncrypt(cl->buff.second+i,cl->dev->Key,tempArray+i);
			else memCpy(tempArray+i,cl->buff.second+i,KEY_SIZE);
		}
		msg.data = tempArray;
		msg.isWrite = TRUE;
		msg.dataSize = askSize;
		if(cl->dev->isSecure) msg.version = 1;
		else msg.version = 0;
		msg.deviceID = cl->dev->Id;
		if(!formFrame(cl->buff.first,cl->buff.second,&msg)) { // Формируем пакет данных
			count = 0xFF;
			break;
		}
		count++;
		registerCallBack(DeviceReadWork,count,(BaseParam_t)cl,(void*)((u32*)sendToClient + cl->sessionId));
		SetTask((TaskMng)sendToClient,cl->sessionId, (BaseParam_t)(&cl->buff));
		return;
	case 2: // Ждем подтверждения о получении
		count++;
		registerCallBack(DeviceReadWork, count, (BaseParam_t)cl, (void*)((u32*)receiveFromClient+cl->sessionId));
		SetTask((TaskMng)receiveFromClient, cl->sessionId, (BaseParam_t)(&cl->buff));
		return;
	case 3: // ОК шифрованный
		count=5; // TODO Перескакиваем отправку ОК
		msg.data = tempArray;
		msg.dataSize = PROTOCOL_BUFFER_SIZE;
		if(parseFrame(cl->buff.first,cl->buff.second,&msg) > 0) {
			switch(msg.version) {
			case 0:  cl->dev->isSecure = FALSE; break;
			case 1:  cl->dev->isSecure = TRUE; break;
			default: cl->dev->isSecure = FALSE;
			}
			u08 temp[KEY_SIZE]; // OK это не большой объем данных (размера в один ключ хватит с головой)
			if(cl->dev->isSecure) AesEcbDecrypt(msg.data,cl->dev->Key,temp);
			else memCpy(temp,msg.data,KEY_SIZE);
			if(findStr(OK,(string_t)temp) >= 0) {
				writeLogStr("RX OK find\r\n");
			}else {
				writeLogTempString("ERROR: RX not OK\r\n");
				count = 0xFF; break;
			}
		}
		else {
			writeLogTempString("ERROR: Parse not OK\r\n");
			count = 0xFF; break;
		}
		break;
	case 4: // Отправляем ОК (для надежности)
		msg.data = (byte_ptr)OK;
		msg.dataSize = strSize(OK);
		msg.deviceID = cl->dev->Id;
		msg.isWrite = TRUE;
		if(cl->dev->isSecure) msg.version = 1;
		else msg.version = 0;
		while((msg.dataSize & 0x0F) & 0x0F) msg.dataSize++;
		if(cl->dev->isSecure) {
			AesEcbEncrypt(msg.data,cl->dev->Key,tempArray);
			msg.data = tempArray;
		}
		if(!formFrame(cl->buff.first,cl->buff.second,&msg)) {
			count = 0xFF;
			break;
		}
		changeCallBackLabel((void*)((u32*)DeviceReadWork + cl->sessionId), (void*)((u32*)sendToClient+cl->sessionId));
		SetTask((TaskMng)sendToClient,cl->sessionId,(BaseParam_t)(&cl->buff));
		return;
	default:
		execCallBack((void*)((u32*)DeviceReadWork + cl->sessionId));
		return;
	}
	SetTask(DeviceReadWork,count,(BaseParam_t)cl);
}

// При пинге сервер вернет свой идентификатор (начальные байты адреса)
static void pingServer(BaseSize_t deviceID, BaseParam_t client) {
	Client_t* cl = (Client_t*)client;
	message_t msg;
	msg.deviceID = deviceID;
	msg.isWrite = FALSE;
	msg.version = 0;   // Ответ пинга не шифруем
	msg.data = servID; // Отправляем адрес (порт) на котором работает сервер
	msg.dataSize = 16; // Размер идентификатора зависит от системы и клиент должен сам знать какой размер но не больше 16 байт
	if(formFrame(cl->buff.first,cl->buff.second, &msg)) {
		writeLogStr("PING!");
		changeCallBackLabel(((u32*)pingServer + cl->sessionId), ((u32*)sendToClient+cl->sessionId));
		SetTask((TaskMng)sendToClient, cl->sessionId, (BaseParam_t)(&cl->buff));
		return;
	}
	execCallBack((void*)((u32*)pingServer + cl->sessionId));
}

// Расшифровуем полученные данные и вызываем соответсвующие функции чтения или записи
static void ClientWork(BaseSize_t arg_n, BaseParam_t client) {
	Client_t* cl = (Client_t*)client;
	u08 buff[PROTOCOL_BUFFER_SIZE]; // Для разшифровки полученного сообщения
	message_t msg;
	msg.data = buff;
	msg.dataSize = PROTOCOL_BUFFER_SIZE;
	u16 effectiveSize = parseFrame(cl->buff.first,cl->buff.second, &msg); // Парсим сообщение (проверка контрольной суммы)
	if(msg.deviceID != 0 && effectiveSize > 0) {	// Если парсинг сообщения прошел успешно
		cl->dev = findDeviceById(msg.deviceID);	// Пытаемся найти идентификатор
		if(cl->dev != NULL) { // Нашли такое устройство
			switch(msg.version) {
					case 0: cl->isSecureSession = FALSE; break;  // Сохраняем протокол по которому работает клиент
					case 1: cl->isSecureSession = TRUE; if(!cl->dev->isSecure){writeLogStr("ERROR: Security synhro");} break;
					default: cl->isSecureSession = FALSE;  // Undefine version type
			}
			for(u08 i = 0; i<cl->buff.first; i+=KEY_SIZE) {
				if(cl->isSecureSession) AesEcbDecrypt(buff+i,cl->dev->Key,cl->buff.second+i); // Расшифровуем полученное сообщение
				else memCpy(cl->buff.second+i, buff+i, KEY_SIZE); // Без шифрования
			}
			if(msg.isWrite) { // Если сообщение на запись данных на сервер
				cl->buff.first = effectiveSize; // Сохраняем размер полезного сообщения
				changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)DeviceWriteWork + cl->sessionId));
				SetTask(DeviceWriteWork,0,(BaseParam_t)cl); // Запуская воркера на запись
				return;
			} else { // Иначе сообщения на чтение с сервера
				changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)DeviceReadWork + cl->sessionId));
				SetTask(DeviceReadWork,0,(BaseParam_t)cl); // Запускаям воркера на чтение
				return;
			}
		}
		else { // Если устройство мы не нашли в списке устройств
			if(msg.deviceID < 0xFF && isAllowRegistration) { //Если разрешена регистрация, то это может быть либо пинг, либо сама регистрация
				if(!msg.isWrite) { //проверяем не ригистрация ли это
					cl->dev = (Device_t*)allocMem(sizeof(Device_t));
					if(cl->dev == NULL) {
						execCallBack((void*)((u32*)ClientWork+cl->sessionId));
						return;
					}
					cl->dev->Id = msg.deviceID;
					changeCallBackLabel((void*)((u32*)ClientWork + cl->sessionId), (void*)((u32*)NewDeviceCreate + cl->sessionId));
					SetTask(NewDeviceCreate,0,(BaseParam_t)cl);
					return;
				}
				else { // Значит это пинг сервера
					changeCallBackLabel(((u32*)ClientWork + cl->sessionId),((u32*)pingServer+cl->sessionId));
					SetTask(pingServer,msg.deviceID,(BaseParam_t)cl);
					return;
				}
			}
		}
	}
	execCallBack((void*)((u32*)ClientWork+cl->sessionId));
	return;
}

void initServer(u08 channel, byte_ptr serverID) {
	servID = serverID; // Сохраняем для пинга
	changeCallBackLabel(initServer,initTransportLayer);
	initTransportLayer(channel, serverID);
}

static void initializeList() {
	DeviceList = createNewList(NULL);
	changeCallBackLabel(initializeList,(void*)getAllParameters);
	getAllParameters(DeviceList);
}

static void mainServerThread() {
	u16 sessionId = getNextReadyDevice();
	if(sessionId) {
		Client_t* c = (Client_t*)allocMem(sizeof(Client_t));
		if(c != NULL) { // Удалось создать клиента
			c->sessionId = sessionId;
			c->buff.first = PROTOCOL_BUFFER_SIZE;
			c->buff.second = allocMem(c->buff.first);
			if(c->buff.second != NULL) {
				registerCallBack((TaskMng)freeClient,sessionId,(BaseParam_t)c,(void*)((u32*)ClientWork+sessionId));
				registerCallBack(ClientWork, 0, (BaseParam_t)c, (void*)((u32*)receiveFromClient+sessionId));
				SetTask((TaskMng)receiveFromClient, sessionId, (BaseParam_t)(&c->buff));
			}
			else {
				freeMem((byte_ptr)c);
				writeLogStr("ERROR: memmory allocate for client buffer");
				defragmentation();
				writeLogU32(getFreeMemmorySize());
			}
		}
		else {
			writeLogStr("ERROR: memmory allocate for client session");
			defragmentation();
			writeLogU32(getFreeMemmorySize());
		}
	}
}

void SetClientHandlers(TaskMng writeHandler, TaskMng readHandler) {
	if(writeHandler != NULL) WriteHandler = writeHandler;
	if(readHandler != NULL)  ReadHandler = readHandler;
}

void ServerIotWork(BaseSize_t arg_n, BaseParam_t arg_p) {
	writeLogStr("Start work server");
	if(DeviceList == NULL) {
		registerCallBack(ServerIotWork,arg_n,arg_p,initializeList);
		initializeList();
		return;
	}
	SetCycleTask(TIME_DELAY_IF_BUSY,mainServerThread,TRUE);
}

void PushToDevice(BaseSize_t deviceID, BaseParam_t buff) {

}
