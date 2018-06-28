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
#include "hostDriverAPI.h"

#ifndef NULL
#define NULL 0
#endif

static byte_ptr servID = NULL; // Для ПИНГА
static ListNode_t* DeviceList = NULL; // Хранит указатель на голову списка устройств
static ListNode_t* PushedList = NULL; // Хранит указатель на голову списка устройств с пушами
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

static PushDev_t* findPushedDeviceById(u16 devId) {
	PushDev_t* res = NULL;
	ListNode_t* head = findHead(PushedList);
	if(head == NULL) return res;
	while( (head = head->next) != NULL ) {
		if(head->data == NULL) break;
		res = ((PushDev_t*)(head->data));
		if( res->dev->Id == devId ) {
			break;
		}
		res = NULL;
	}
	return res;
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
	writeLogWhithStr("INFO: Free session:", sessionId);
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
		memCpy(cl->dev->Key,&(cl->dev->Id), sizeof(cl->dev->Id)); // В младшие два байта ключа шифрования копируем идентификатор
		// Этот кастыль связан с тем что нет возможности отправить данные больше чем размер одного ключа шифрования
		if(putToEndList(DeviceList,(void*)cl->dev, sizeof(Device_t)) == NULL) { // Записываем новое устройство в список всех устройств
			writeLogStr("ERROR: DeviceList overflow\r\n");
			count = 0xFF;
			break;
		}
		count++;
		// no break;
	case 1: //Формируем ответ клиенту с генерированными данными
		 // Отправляем запрос без шифрования если это вновь зарегистрированное устройство
		msg.data = cl->dev->Key; // Два младших бита отданы на идентификатор
		msg.dataSize = KEY_SIZE;
		msg.messageID = 0;
		msg.messageType = SimpleWrite;
		msg.isSecure = FALSE;
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
	case 3: // Парсим ответ о подтверждении приема сгенерированных данных
		count++;
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
				count++;
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
		if(cl->newKey == NULL) {count=0xFF;	break;}
		generateKey(cl->newKey);
		cl->newKey[0] = getTypeById(cl->dev->Id); // Младший байт ключа ВСЕГДА ТИП УСТРОЙСТВА (это сделано для исключения рассинхронизации обмена)
		// Эти данные равны длине ключа шифрования
		if(cl->dev->isSecure) AesEcbEncrypt(cl->newKey,cl->dev->Key,tempBuff); // Шифруем старым ключом
		else memCpy(tempBuff,cl->newKey,KEY_SIZE);
		msg.data = tempBuff;
		msg.messageType = SimpleWrite;
		msg.messageID = 0;
		msg.dataSize = KEY_SIZE;
		msg.isSecure = cl->dev->isSecure;
		msg.deviceID = cl->dev->Id;
		if(!formFrame(cl->buff.first,cl->buff.second,&msg)){
			writeLogStr("ERROR: Can not form frame"); count = 0xFF;	break;
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
		msg.data = tempBuff;
		msg.dataSize = KEY_SIZE;
		if(parseFrame(getAllocateMemmorySize(cl->buff.second),cl->buff.second,&msg) > 0) {
			cl->dev->isSecure = msg.isSecure;
			u08 temp[KEY_SIZE]; // OK это не большой объем данных (размера в один ключ хватит с головой)
			if(cl->dev->isSecure) AesEcbDecrypt(msg.data,cl->newKey,temp);
			else memCpy(temp,msg.data,KEY_SIZE);
			if(findStr(OK,(string_t)temp) >= 0) { // подтверждение отправляется без шифрования
				cl->dev->isSecure = cl->isSecureSession;
				memCpy(cl->dev->Key,cl->newKey,KEY_SIZE);
				count++;
				registerCallBack(DeviceWriteWork,count, (BaseParam_t)cl, (u32*)updateDevice + cl->dev->Id);
				updateDevice(cl->dev);
				writeLogStr("INFO: TX OK finded\r\n");
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
				if(cl->buff.second == NULL) { // Места не хватило попробуем прочитать хоть что-то
					count++;
					cl->buff.second = tempBuff;
					cl->buff.first = getAllocateMemmorySize(cl->buff.second);
					registerCallBack(DeviceReadWork,count,(BaseParam_t)cl, (u32*)ReadHandler+cl->dev->Id); // Ожидаем ответа
					SetTask(ReadHandler, cl->dev->Id, (BaseParam_t)(&cl->buff));
					return; // Ожидаем колбэк со сформированным ответом
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
		count = 0xFF; // Не предусмотрен обработчик на чтение
		break;
	case 1: // в cl->buf.second содержится ответ
		askSize = cl->buff.first; // Сохраняем запрашиваемый размер буфера (этот размер мы и передадим)
		cl->buff.first = getAllocateMemmorySize(cl->buff.second); // Востанавливаем исходный размер буфера
		if(cl->dev->isSecure) {
			askSize = KEY_SIZE;
			AesEcbEncrypt(cl->buff.second,cl->dev->Key,tempArray);
		}
		else memCpy(tempArray,cl->buff.second,KEY_SIZE);
		msg.data = tempArray;
		msg.messageType = SimpleWrite;
		msg.messageID = 0;
		msg.dataSize = askSize;
		msg.isSecure = cl->dev->isSecure;
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
		count++;
		msg.data = tempArray;
		msg.dataSize = PROTOCOL_BUFFER_SIZE;
		if(parseFrame(cl->buff.first,cl->buff.second,&msg) > 0) {
			cl->dev->isSecure = msg.isSecure;
			u08 temp[KEY_SIZE]; // OK это не большой объем данных (размера в один ключ хватит с головой)
			if(cl->dev->isSecure) AesEcbDecrypt(msg.data,cl->dev->Key,temp);
			else memCpy(temp,msg.data,KEY_SIZE);
			if(findStr(OK,(string_t)temp) >= 0) {
				writeLogStr("INFO: RX OK find\r\n");
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
	msg.messageID = 0;
	msg.messageType = SimpleRead;
	msg.isSecure = FALSE;   // Ответ пинга не шифруем
	msg.data = servID; // Отправляем адрес (порт) на котором работает сервер
	msg.dataSize = KEY_SIZE; // Размер идентификатора зависит от системы и клиент должен сам знать какой размер но не больше размера ключа
	if(formFrame(cl->buff.first,cl->buff.second, &msg)) {
		writeLogStr("PING!");
		changeCallBackLabel(((u32*)pingServer + cl->sessionId), ((u32*)sendToClient+cl->sessionId));
		SetTask((TaskMng)sendToClient, cl->sessionId, (BaseParam_t)(&cl->buff));
		return;
	}
	execCallBack((void*)((u32*)pingServer + cl->sessionId));
}

static void deviceOkLogic(Client_t *cl, message_t* msg, byte_ptr buff) {
	if(msg->isSecure) {
		cl->isSecureSession = TRUE;
		if(!cl->dev->isSecure) writeLogStr("ERROR: Security synhro");
	} else {
		cl->isSecureSession = FALSE;  // Сохраняем протокол по которому работает клиент
		writeLogStr("WARN: Session not secure");
	}
	if(cl->isSecureSession) AesEcbDecrypt(buff,cl->dev->Key,cl->buff.second); // Расшифровуем полученное сообщение
	else memCpy(cl->buff.second, buff, KEY_SIZE); // Без шифрования
	switch(msg->messageType) { // Устройство известное.
	case SimpleWrite: // сообщение на запись данных на сервер
		changeCallBackLabel((void*)((u32*)deviceOkLogic + cl->sessionId), (void*)((u32*)DeviceWriteWork + cl->sessionId));
		SetTask(DeviceWriteWork,0,(BaseParam_t)cl); // Запуская воркера на запись
		return;
	case SimpleRead: // сообщения на чтение с сервера
		changeCallBackLabel((void*)((u32*)deviceOkLogic + cl->sessionId), (void*)((u32*)DeviceReadWork + cl->sessionId));
		SetTask(DeviceReadWork,0,(BaseParam_t)cl); // Запускаям воркера на чтение
		return;
	case SimplePush: // Известное устройство хочет что-то запушить
		// FIXME Not implemented yet
		execCallBack((void*)((u32*)deviceOkLogic+cl->sessionId));
		return;
	}
	execCallBack((void*)((u32*)deviceOkLogic+cl->sessionId));
}

static void deviceNotOkLogic(Client_t* cl, message_t* msg){
	if(msg->deviceID < 0xFF && isAllowRegistration) { //Если разрешена регистрация
		//то это может быть либо пинг, либо сама регистрация
		switch(msg->messageType){
		case SimpleWrite: // ПИНГ
			changeCallBackLabel(((u32*)deviceNotOkLogic + cl->sessionId),((u32*)pingServer+cl->sessionId));
			SetTask(pingServer,msg->deviceID,(BaseParam_t)cl);
			return;
		case SimpleRead: // РЕГИСТРАЦИЯ
			cl->dev = (Device_t*)allocMem(sizeof(Device_t));
			if(cl->dev == NULL) {
				execCallBack((void*)((u32*)deviceNotOkLogic+cl->sessionId));
				return;
			}
			cl->dev->Id = msg->deviceID;
			changeCallBackLabel((void*)((u32*)deviceNotOkLogic + cl->sessionId), (void*)((u32*)NewDeviceCreate + cl->sessionId));
			SetTask(NewDeviceCreate,0,(BaseParam_t)cl);
			return;
		case SimplePush:
			// Not implemented yet
			execCallBack((void*)((u32*)deviceNotOkLogic+cl->sessionId));
			return;
		}
	}
	execCallBack((void*)((u32*)deviceNotOkLogic+cl->sessionId));
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
			msg.dataSize = effectiveSize; // Сохраняем реальный размер сообщения
			writeLogStr("INFO: DeviceId finded");
			changeCallBackLabel(((u32*)ClientWork + cl->sessionId),((u32*)deviceOkLogic + cl->sessionId));
			deviceOkLogic(cl,&msg,buff);
			return;
		}
		else { // Если устройство мы не нашли в списке устройств
			writeLogStr("INFO: DeviceId not find");
			changeCallBackLabel(((u32*)ClientWork + cl->sessionId),((u32*)deviceNotOkLogic + cl->sessionId));
			deviceNotOkLogic(cl,&msg);
			return;
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

void SetClientHandlers(TaskMng writeHandler, TaskMng readHandler) {
	if(writeHandler != NULL) WriteHandler = writeHandler;
	if(readHandler != NULL)  ReadHandler = readHandler;
}


static void initializeList() {
	DeviceList = createNewList(NULL);
	PushedList = createNewList(NULL);
	registerCallBack((TaskMng)getAllPushedDevice,0,(BaseParam_t)PushedList,getAllParameters);
	changeCallBackLabel(initializeList,(void*)getAllPushedDevice);
	SetTask((TaskMng)getAllParameters,0, DeviceList);
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

void ServerIotWork(BaseSize_t arg_n, BaseParam_t arg_p) {
	writeLogStr("INFO: Start work server");
	if(DeviceList == NULL) {
		registerCallBack(ServerIotWork,arg_n,arg_p,initializeList);
		initializeList();
		return;
	}
	SetCycleTask(2,mainServerThread,TRUE);
}

static void answerPushedDevice(BaseSize_t arg_n, channelBuff_t* chan) { // Расшифровка полученого ответа от устройства
	static u08 temp[KEY_SIZE]; // Должен быть в памяти всегда
	if(chan == NULL) {
		execCallBack(answerPushedDevice);
		return;
	}
	u08 buff[KEY_SIZE];
	memSet(temp,KEY_SIZE,0); // Очистим память перед анализом
	message_t msg;
	msg.data = temp;
	msg.dataSize = KEY_SIZE; // Ответ больше чем размер ключа быть НЕ ДОЛЖЕН
	u08 sz = parseFrame(chan->pipe.dataLength, chan->buff, &msg);
	if(sz > 0) {
		PushDev_t* dev = findPushedDeviceById(msg.deviceID);
		if(dev != NULL) {
			if(dev->dev->isSecure) {
				AesEcbDecrypt(msg.data,dev->dev->Key,buff);
				memCpy(msg.data,buff,KEY_SIZE);
			}
			emitSignal((void*)AnswerAnalize,KEY_SIZE,msg.data);
		}
	}
	freeMem(chan->buff);
	freeMem((byte_ptr)chan);
	execCallBack(answerPushedDevice);
}

const void* const AnswerAnalize = answerPushedDevice;

void PushToDevice(BaseSize_t deviceID, ClientData_t* buff) {
	PushDev_t* dev = findPushedDeviceById(deviceID);
	if(dev != NULL) {
		if(buff->first >= dev->chan.dataLength) {
			// Если размер передаваемых данных больше чем ширина канала
			writeLogStr("ERROR: Incorrect message size");
			execCallBack((u32*)PushToDevice+deviceID);
			return;
		}
		channelBuff_t* client = (channelBuff_t*)allocMem(sizeof(channelBuff_t));
		if(client == NULL) {
			writeLogStr("ERROR: Can not push to device. Memmory error");
			execCallBack((u32*)PushToDevice+deviceID);
			return;
		}
		byte_ptr data = allocMem(dev->chan.dataLength);  // Сдесь сохранится само сообщение
		if(data == NULL) {
			freeMem((byte_ptr)client);
			writeLogStr("ERROR: Memmory error");
			execCallBack((u32*)PushToDevice+deviceID);
			return;
		}
		message_t msg;
		if(dev->dev->isSecure && (buff->first >= KEY_SIZE) ) {
			AesEcbEncrypt(buff->second,dev->dev->Key,data); // Шифруем данные
			memCpy(buff->second,data,KEY_SIZE); // И копируем уже зашифрованные данные назад
			msg.isSecure = TRUE;
			msg.dataSize = KEY_SIZE; // Если сообщение удалось зашифровать (передаем максимально возможный объем информации)
		}
		else {
			msg.isSecure = FALSE;		// Если сообщение не большое, или устройство работает по не зашифрованному каналу
			msg.dataSize = buff->first;	// Передаем само сообщение без зашифровки
		}
		msg.data = buff->second;
		msg.deviceID = dev->dev->Id;
		msg.messageID = 0;
		msg.messageType = SimplePush;
		if(formFrame(dev->chan.dataLength,data,&msg)) {
			client->buff = data;
			memCpy(&client->pipe,&dev->chan,sizeof(channel_t));
			registerCallBack((TaskMng)answerPushedDevice,0,(BaseParam_t)client,(u32*)pushToClient+client->pipeNumber);
			changeCallBackLabel((u32*)PushToDevice+deviceID,answerPushedDevice);
			SetTask((TaskMng)pushToClient,0,(BaseParam_t)client);
			return;
		}
		writeLogStr("ERROR: Can not push message. Form frame error");
		freeMem(data);
		freeMem((byte_ptr)client);
		execCallBack((u32*)PushToDevice+deviceID);
		return;
	}
	writeLogStr("ERROR: Push device not found");
	execCallBack((u32*)PushToDevice+deviceID);
}
